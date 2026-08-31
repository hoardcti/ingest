package store

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// WriteBatch writes one canonicalised envelope in a single transaction.
//
// The shape of the write is deliberate. Row-by-row upserts of fifty thousand
// indicators would spend the entire time in round trips, so entities go in
// through the COPY protocol into a staging table and are merged with one
// INSERT ... SELECT ... ON CONFLICT DO UPDATE. Everything downstream of that
// merge is one statement per table, not one per row.
//
// A duplicate envelope — the same content hash already recorded for this source
// — writes nothing and returns WriteResult.Duplicate. At-least-once delivery
// guarantees this will happen, so it is a normal outcome and not an error.
func (s *Store) WriteBatch(ctx context.Context, b *Batch) (WriteResult, error) {
	start := time.Now()
	var res WriteResult

	if len(b.Records) == 0 && len(b.Relationships) == 0 {
		return res, fmt.Errorf("batch from %q is empty", b.SourceSlug)
	}

	src, err := s.ResolveSource(ctx, b.SourceSlug)
	if err != nil {
		return res, err
	}
	res.SourceID = src.ID

	// Provisioned before the transaction opens: CREATE TABLE ... PARTITION OF
	// takes ACCESS EXCLUSIVE on the parent, and holding that for the duration
	// of a bulk COPY would stall every other writer and reader of sighting.
	if err := s.ensureSightingPartitions(ctx, b); err != nil {
		return res, err
	}

	err = s.inTx(ctx, func(tx pgx.Tx) error {
		claimed, err := claimEnvelope(ctx, tx, src.ID, b)
		if err != nil {
			return err
		}
		if !claimed {
			res.Duplicate = true
			return nil
		}

		ids, err := upsertEntities(ctx, tx, b)
		if err != nil {
			return err
		}
		res.Entities = make([]EntityRef, 0, len(ids))
		for k, id := range ids {
			res.Entities = append(res.Entities, EntityRef{
				Kind: k.kind, CanonicalKey: k.key, ID: id.String(),
			})
		}

		if res.Indicators, err = upsertIndicators(ctx, tx, b, ids); err != nil {
			return err
		}
		if res.CVEs, err = upsertCVEs(ctx, tx, b, ids); err != nil {
			return err
		}
		if res.Breaches, err = upsertBreaches(ctx, tx, b, ids); err != nil {
			return err
		}
		if res.Sightings, err = copySightings(ctx, tx, b, src.ID, ids); err != nil {
			return err
		}
		if res.Relationships, err = upsertRelationships(ctx, tx, b, ids); err != nil {
			return err
		}

		return finishEnvelope(ctx, tx, src.ID, b, res.Sightings)
	})
	if err != nil {
		return res, err
	}

	res.Elapsed = time.Since(start)
	return res, nil
}

// claimEnvelope takes the idempotency row. It returns false when this envelope
// has already been processed for this source.
//
// The claim is part of the ingest transaction, which is what makes it correct:
// a consumer that dies after COMMIT but before acknowledging the queue will be
// handed the same envelope again and find the claim already taken. A consumer
// that dies mid-transaction rolls the claim back with everything else, and the
// retry does the work properly.
func claimEnvelope(ctx context.Context, tx pgx.Tx, sourceID pgtype.UUID, b *Batch) (bool, error) {
	tag, err := tx.Exec(ctx, `
		INSERT INTO ingest_envelope
			(source_id, envelope_digest, content_hash, source_run_id,
			 schema_version, record_count, raw_ref)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), $5, $6, NULLIF($7, ''))
		ON CONFLICT (source_id, envelope_digest) DO NOTHING`,
		sourceID, b.EnvelopeDigest, b.ContentHash, b.SourceRunID,
		b.SchemaVersion, len(b.Records), b.RawRef)
	if err != nil {
		return false, fmt.Errorf("claim envelope %s: %w", b.EnvelopeDigest, err)
	}
	return tag.RowsAffected() == 1, nil
}

func finishEnvelope(ctx context.Context, tx pgx.Tx, sourceID pgtype.UUID, b *Batch, sightings int) error {
	if _, err := tx.Exec(ctx, `
		UPDATE ingest_envelope
		SET processed_at = now(), record_count = $3, raw_ref = COALESCE(NULLIF($4, ''), raw_ref)
		WHERE source_id = $1 AND envelope_digest = $2`,
		sourceID, b.EnvelopeDigest, sightings, b.RawRef); err != nil {
		return fmt.Errorf("mark envelope processed: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE source SET last_run_at = GREATEST(COALESCE(last_run_at, $2), $2) WHERE id = $1`,
		sourceID, b.CollectedAt); err != nil {
		return fmt.Errorf("update source last_run_at: %w", err)
	}
	return nil
}

// upsertEntities merges every entity in the batch — records and relationship
// endpoints alike — and returns their database ids.
func upsertEntities(ctx context.Context, tx pgx.Tx, b *Batch) (map[entityKey]pgtype.UUID, error) {
	stage := make([]Entity, 0, len(b.Records)+2*len(b.Relationships))
	for i := range b.Records {
		stage = append(stage, b.Records[i].Entity)
	}
	for i := range b.Relationships {
		r := &b.Relationships[i]
		stage = append(stage,
			Entity{Kind: r.SourceKind, CanonicalKey: r.SourceKey, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen},
			Entity{Kind: r.TargetKind, CanonicalKey: r.TargetKey, FirstSeen: r.FirstSeen, LastSeen: r.LastSeen},
		)
	}

	if _, err := tx.Exec(ctx, `
		CREATE TEMP TABLE stage_entity (
			kind          text        NOT NULL,
			canonical_key text        NOT NULL,
			first_seen    timestamptz NOT NULL,
			last_seen     timestamptz NOT NULL
		) ON COMMIT DROP`); err != nil {
		return nil, fmt.Errorf("create staging table: %w", err)
	}

	_, err := tx.CopyFrom(ctx,
		pgx.Identifier{"stage_entity"},
		[]string{"kind", "canonical_key", "first_seen", "last_seen"},
		pgx.CopyFromSlice(len(stage), func(i int) ([]any, error) {
			e := stage[i]
			return []any{e.Kind, e.CanonicalKey, e.FirstSeen, e.LastSeen}, nil
		}))
	if err != nil {
		return nil, fmt.Errorf("copy %d entities into staging: %w", len(stage), err)
	}

	// GROUP BY collapses duplicates within the batch: ON CONFLICT DO UPDATE
	// refuses to touch the same row twice in one statement, and a feed listing
	// the same indicator under two tags is entirely normal.
	//
	// ORDER BY is not cosmetic. Two concurrent batches touching overlapping
	// entities must take row locks in the same order or they will deadlock,
	// and GROUP BY alone gives no ordering guarantee.
	rows, err := tx.Query(ctx, `
		INSERT INTO entity (kind, canonical_key, first_seen, last_seen)
		SELECT kind, canonical_key, min(first_seen), max(last_seen)
		FROM stage_entity
		GROUP BY kind, canonical_key
		ORDER BY kind, canonical_key
		ON CONFLICT (kind, canonical_key) DO UPDATE SET
			first_seen = LEAST(entity.first_seen, EXCLUDED.first_seen),
			last_seen  = GREATEST(entity.last_seen, EXCLUDED.last_seen)
		RETURNING id, kind, canonical_key`)
	if err != nil {
		return nil, fmt.Errorf("merge entities: %w", err)
	}
	defer rows.Close()

	ids := make(map[entityKey]pgtype.UUID, len(stage))
	for rows.Next() {
		var (
			id   pgtype.UUID
			k    entityKey
			kind string
			key  string
		)
		if err := rows.Scan(&id, &kind, &key); err != nil {
			return nil, fmt.Errorf("scan merged entity: %w", err)
		}
		k = entityKey{kind: kind, key: key}
		ids[k] = id
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("merge entities: %w", err)
	}
	return ids, nil
}

// upsertIndicators writes the indicator module rows.
//
// This is the highest-volume module by a wide margin, so it goes in through
// parallel arrays and unnest rather than a JSON round trip — every column is a
// scalar, so there is nothing to gain from the heavier encoding.
func upsertIndicators(ctx context.Context, tx pgx.Tx, b *Batch, ids map[entityKey]pgtype.UUID) (int, error) {
	byID := make(map[pgtype.UUID]*IndicatorFields)
	for i := range b.Records {
		r := &b.Records[i]
		if r.Indicator == nil {
			continue
		}
		id, ok := ids[entityKey{kind: r.Entity.Kind, key: r.Entity.CanonicalKey}]
		if !ok {
			return 0, fmt.Errorf("indicator %q has no entity id", r.Entity.CanonicalKey)
		}
		byID[id] = r.Indicator
	}
	if len(byID) == 0 {
		return 0, nil
	}

	order := sortedIDs(byID)
	entityIDs := make([]pgtype.UUID, len(order))
	types := make([]string, len(order))
	values := make([]string, len(order))
	rawValues := make([]*string, len(order))
	for i, id := range order {
		f := byID[id]
		entityIDs[i] = id
		types[i] = f.Type
		values[i] = f.Value
		if f.RawValue != "" && f.RawValue != f.Value {
			raw := f.RawValue
			rawValues[i] = &raw
		}
	}

	tag, err := tx.Exec(ctx, `
		INSERT INTO indicator (entity_id, type, value, raw_value)
		SELECT * FROM unnest($1::uuid[], $2::text[], $3::text[], $4::text[])
		ON CONFLICT (entity_id) DO UPDATE SET
			type      = EXCLUDED.type,
			value     = EXCLUDED.value,
			raw_value = COALESCE(EXCLUDED.raw_value, indicator.raw_value)`,
		entityIDs, types, values, rawValues)
	if err != nil {
		return 0, fmt.Errorf("upsert %d indicators: %w", len(order), err)
	}
	return int(tag.RowsAffected()), nil
}

// cveRow mirrors the column list of the jsonb_to_recordset below. CVE carries a
// text[] and a jsonb, neither of which survives a trip through unnest, so the
// whole set goes over as one JSON document.
type cveRow struct {
	EntityID       pgtype.UUID `json:"entity_id"`
	CVEID          string      `json:"cve_id"`
	Summary        *string     `json:"summary"`
	CVSSScore      *float64    `json:"cvss_score"`
	CVSSVector     *string     `json:"cvss_vector"`
	Severity       *string     `json:"severity"`
	EPSSScore      *float64    `json:"epss_score"`
	KnownExploited bool        `json:"known_exploited"`
	CWE            []string    `json:"cwe"`
	PublishedAt    *time.Time  `json:"published_at"`
	ModifiedAt     *time.Time  `json:"modified_at"`
	Refs           []any       `json:"refs"`
}

func upsertCVEs(ctx context.Context, tx pgx.Tx, b *Batch, ids map[entityKey]pgtype.UUID) (int, error) {
	byID := make(map[pgtype.UUID]*CVEFields)
	for i := range b.Records {
		r := &b.Records[i]
		if r.CVE == nil {
			continue
		}
		id, ok := ids[entityKey{kind: r.Entity.Kind, key: r.Entity.CanonicalKey}]
		if !ok {
			return 0, fmt.Errorf("cve %q has no entity id", r.Entity.CanonicalKey)
		}
		byID[id] = r.CVE
	}
	if len(byID) == 0 {
		return 0, nil
	}

	rows := make([]cveRow, 0, len(byID))
	for _, id := range sortedIDs(byID) {
		f := byID[id]
		rows = append(rows, cveRow{
			EntityID:       id,
			CVEID:          f.CVEID,
			Summary:        f.Summary,
			CVSSScore:      f.CVSSScore,
			CVSSVector:     f.CVSSVector,
			Severity:       f.Severity,
			EPSSScore:      f.EPSSScore,
			KnownExploited: f.KnownExploited,
			CWE:            f.CWE,
			PublishedAt:    f.PublishedAt,
			ModifiedAt:     f.ModifiedAt,
			Refs:           f.Refs,
		})
	}
	payload, err := json.Marshal(rows)
	if err != nil {
		return 0, fmt.Errorf("encode cve rows: %w", err)
	}

	// COALESCE on every optional column: an enrichment feed that only knows the
	// EPSS score must not blank out the summary another feed supplied.
	//
	// known_exploited is an OR rather than a COALESCE. CISA KEV is additive —
	// a feed that does not mention exploitation is not asserting its absence,
	// and letting it clear the flag would be a genuine security regression.
	tag, err := tx.Exec(ctx, `
		INSERT INTO cve (entity_id, cve_id, summary, cvss_score, cvss_vector, severity,
		                 epss_score, known_exploited, cwe, published_at, modified_at, refs)
		SELECT r.entity_id, r.cve_id, r.summary, r.cvss_score, r.cvss_vector, r.severity,
		       r.epss_score, COALESCE(r.known_exploited, false), r.cwe,
		       r.published_at, r.modified_at, r.refs
		FROM jsonb_to_recordset($1::jsonb) AS r(
			entity_id       uuid,
			cve_id          text,
			summary         text,
			cvss_score      real,
			cvss_vector     text,
			severity        text,
			epss_score      real,
			known_exploited boolean,
			cwe             text[],
			published_at    timestamptz,
			modified_at     timestamptz,
			refs            jsonb)
		ORDER BY r.entity_id
		ON CONFLICT (entity_id) DO UPDATE SET
			cve_id          = EXCLUDED.cve_id,
			summary         = COALESCE(EXCLUDED.summary, cve.summary),
			cvss_score      = COALESCE(EXCLUDED.cvss_score, cve.cvss_score),
			cvss_vector     = COALESCE(EXCLUDED.cvss_vector, cve.cvss_vector),
			severity        = COALESCE(EXCLUDED.severity, cve.severity),
			epss_score      = COALESCE(EXCLUDED.epss_score, cve.epss_score),
			known_exploited = cve.known_exploited OR EXCLUDED.known_exploited,
			cwe             = COALESCE(EXCLUDED.cwe, cve.cwe),
			published_at    = COALESCE(EXCLUDED.published_at, cve.published_at),
			modified_at     = GREATEST(EXCLUDED.modified_at, cve.modified_at),
			refs            = COALESCE(EXCLUDED.refs, cve.refs)`,
		payload)
	if err != nil {
		return 0, fmt.Errorf("upsert %d cves: %w", len(rows), err)
	}
	return int(tag.RowsAffected()), nil
}

type breachRow struct {
	EntityID    pgtype.UUID `json:"entity_id"`
	Slug        string      `json:"slug"`
	Name        string      `json:"name"`
	Domain      *string     `json:"domain"`
	Description *string     `json:"description"`
	BreachDate  *string     `json:"breach_date"`
	DisclosedAt *time.Time  `json:"disclosed_at"`
	RecordCount *int64      `json:"record_count"`
	DataClasses []string    `json:"data_classes"`
	Verified    bool        `json:"verified"`
}

func upsertBreaches(ctx context.Context, tx pgx.Tx, b *Batch, ids map[entityKey]pgtype.UUID) (int, error) {
	byID := make(map[pgtype.UUID]*BreachFields)
	for i := range b.Records {
		r := &b.Records[i]
		if r.Breach == nil {
			continue
		}
		id, ok := ids[entityKey{kind: r.Entity.Kind, key: r.Entity.CanonicalKey}]
		if !ok {
			return 0, fmt.Errorf("breach %q has no entity id", r.Entity.CanonicalKey)
		}
		byID[id] = r.Breach
	}
	if len(byID) == 0 {
		return 0, nil
	}

	rows := make([]breachRow, 0, len(byID))
	for _, id := range sortedIDs(byID) {
		f := byID[id]
		row := breachRow{
			EntityID:    id,
			Slug:        f.Slug,
			Name:        f.Name,
			Domain:      f.Domain,
			Description: f.Description,
			DisclosedAt: f.DisclosedAt,
			RecordCount: f.RecordCount,
			DataClasses: f.DataClasses,
			Verified:    f.Verified,
		}
		if f.BreachDate != nil && !f.BreachDate.IsZero() {
			d := f.BreachDate.Format("2006-01-02")
			row.BreachDate = &d
		}
		rows = append(rows, row)
	}
	payload, err := json.Marshal(rows)
	if err != nil {
		return 0, fmt.Errorf("encode breach rows: %w", err)
	}

	tag, err := tx.Exec(ctx, `
		INSERT INTO breach (entity_id, slug, name, domain, description, breach_date,
		                    disclosed_at, record_count, data_classes, verified)
		SELECT r.entity_id, r.slug, r.name, r.domain, r.description, r.breach_date,
		       r.disclosed_at, r.record_count, r.data_classes, COALESCE(r.verified, false)
		FROM jsonb_to_recordset($1::jsonb) AS r(
			entity_id    uuid,
			slug         text,
			name         text,
			domain       text,
			description  text,
			breach_date  date,
			disclosed_at timestamptz,
			record_count bigint,
			data_classes text[],
			verified     boolean)
		ORDER BY r.entity_id
		ON CONFLICT (entity_id) DO UPDATE SET
			slug         = EXCLUDED.slug,
			name         = EXCLUDED.name,
			domain       = COALESCE(EXCLUDED.domain, breach.domain),
			description  = COALESCE(EXCLUDED.description, breach.description),
			breach_date  = COALESCE(EXCLUDED.breach_date, breach.breach_date),
			disclosed_at = COALESCE(EXCLUDED.disclosed_at, breach.disclosed_at),
			record_count = GREATEST(EXCLUDED.record_count, breach.record_count),
			data_classes = COALESCE(EXCLUDED.data_classes, breach.data_classes),
			verified     = breach.verified OR EXCLUDED.verified`,
		payload)
	if err != nil {
		return 0, fmt.Errorf("upsert %d breaches: %w", len(rows), err)
	}
	return int(tag.RowsAffected()), nil
}

// copySightings appends the observation rows. This is the highest-volume write
// in the system and it is append-only, so it goes straight in over COPY with no
// conflict handling at all — two feeds reporting the same indicator twice is
// two sightings, which is the entire point of the table.
func copySightings(ctx context.Context, tx pgx.Tx, b *Batch, sourceID pgtype.UUID, ids map[entityKey]pgtype.UUID) (int, error) {
	type row struct {
		entityID pgtype.UUID
		s        *Sighting
	}
	rows := make([]row, 0, len(b.Records))
	for i := range b.Records {
		r := &b.Records[i]
		if r.Sighting == nil {
			continue // named by a relationship, not observed
		}
		id, ok := ids[entityKey{kind: r.Entity.Kind, key: r.Entity.CanonicalKey}]
		if !ok {
			return 0, fmt.Errorf("sighting for %q has no entity id", r.Entity.CanonicalKey)
		}
		rows = append(rows, row{entityID: id, s: r.Sighting})
	}
	if len(rows) == 0 {
		return 0, nil
	}

	n, err := tx.CopyFrom(ctx,
		pgx.Identifier{"sighting"},
		[]string{"entity_id", "source_id", "observed_at", "content_hash", "raw_ref", "context"},
		pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
			r := rows[i]
			return []any{
				r.entityID, sourceID, r.s.ObservedAt,
				r.s.ContentHash, r.s.RawRef, r.s.Context,
			}, nil
		}))
	if err != nil {
		return 0, fmt.Errorf("copy %d sightings: %w", len(rows), err)
	}
	return int(n), nil
}

type relationshipRow struct {
	SourceID   pgtype.UUID `json:"source_id"`
	TargetID   pgtype.UUID `json:"target_id"`
	Type       string      `json:"type"`
	Confidence *float64    `json:"confidence"`
	FirstSeen  time.Time   `json:"first_seen"`
	LastSeen   time.Time   `json:"last_seen"`
	Metadata   any         `json:"metadata"`
}

func upsertRelationships(ctx context.Context, tx pgx.Tx, b *Batch, ids map[entityKey]pgtype.UUID) (int, error) {
	if len(b.Relationships) == 0 {
		return 0, nil
	}

	type edge struct {
		src, dst pgtype.UUID
		typ      string
	}
	seen := make(map[edge]int, len(b.Relationships))
	rows := make([]relationshipRow, 0, len(b.Relationships))

	for i := range b.Relationships {
		r := &b.Relationships[i]
		srcID, ok := ids[entityKey{kind: r.SourceKind, key: r.SourceKey}]
		if !ok {
			return 0, fmt.Errorf("relationship source %q has no entity id", r.SourceKey)
		}
		dstID, ok := ids[entityKey{kind: r.TargetKind, key: r.TargetKey}]
		if !ok {
			return 0, fmt.Errorf("relationship target %q has no entity id", r.TargetKey)
		}
		if srcID == dstID {
			// A self-edge says nothing and would survive forever. Almost always
			// a feed listing an entity as its own alias.
			continue
		}

		row := relationshipRow{
			SourceID:   srcID,
			TargetID:   dstID,
			Type:       r.Type,
			Confidence: r.Confidence,
			FirstSeen:  r.FirstSeen,
			LastSeen:   r.LastSeen,
		}
		if len(r.Metadata) > 0 {
			row.Metadata = json.RawMessage(r.Metadata)
		}

		// Collapse within the batch, keeping the widest seen window, for the
		// same reason as entities: ON CONFLICT cannot touch a row twice.
		e := edge{src: srcID, dst: dstID, typ: r.Type}
		if j, dup := seen[e]; dup {
			if row.FirstSeen.Before(rows[j].FirstSeen) {
				rows[j].FirstSeen = row.FirstSeen
			}
			if row.LastSeen.After(rows[j].LastSeen) {
				rows[j].LastSeen = row.LastSeen
			}
			if rows[j].Confidence == nil {
				rows[j].Confidence = row.Confidence
			}
			continue
		}
		seen[e] = len(rows)
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		return 0, nil
	}

	slices.SortFunc(rows, func(a, c relationshipRow) int {
		if n := bytes.Compare(a.SourceID.Bytes[:], c.SourceID.Bytes[:]); n != 0 {
			return n
		}
		if n := bytes.Compare(a.TargetID.Bytes[:], c.TargetID.Bytes[:]); n != 0 {
			return n
		}
		return cmpString(a.Type, c.Type)
	})

	payload, err := json.Marshal(rows)
	if err != nil {
		return 0, fmt.Errorf("encode relationship rows: %w", err)
	}

	tag, err := tx.Exec(ctx, `
		INSERT INTO relationship (source_id, target_id, type, confidence,
		                          first_seen, last_seen, metadata)
		SELECT r.source_id, r.target_id, r.type, r.confidence,
		       r.first_seen, r.last_seen, r.metadata
		FROM jsonb_to_recordset($1::jsonb) AS r(
			source_id  uuid,
			target_id  uuid,
			type       text,
			confidence real,
			first_seen timestamptz,
			last_seen  timestamptz,
			metadata   jsonb)
		ORDER BY r.source_id, r.target_id, r.type
		ON CONFLICT (source_id, target_id, type) DO UPDATE SET
			confidence = COALESCE(EXCLUDED.confidence, relationship.confidence),
			first_seen = LEAST(relationship.first_seen, EXCLUDED.first_seen),
			last_seen  = GREATEST(relationship.last_seen, EXCLUDED.last_seen),
			metadata   = COALESCE(relationship.metadata, '{}'::jsonb)
			             || COALESCE(EXCLUDED.metadata, '{}'::jsonb)`,
		payload)
	if err != nil {
		return 0, fmt.Errorf("upsert %d relationships: %w", len(rows), err)
	}
	return int(tag.RowsAffected()), nil
}

// sortedIDs returns the map's keys in byte order, so that concurrent batches
// take row locks in a consistent sequence and cannot deadlock each other.
func sortedIDs[V any](m map[pgtype.UUID]V) []pgtype.UUID {
	out := make([]pgtype.UUID, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	slices.SortFunc(out, func(a, b pgtype.UUID) int {
		return bytes.Compare(a.Bytes[:], b.Bytes[:])
	})
	return out
}

func cmpString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
