-- Core schema: the entity registry, the relationship graph, sources, and
-- sightings. Transcribed from the Drizzle reference schema; see db/README.md
-- for the ownership rules that govern changes here.

-- +goose Up

-- pg_trgm backs fuzzy domain and string matching on indicator values.
-- gen_random_uuid() is built in from PostgreSQL 13, so no pgcrypto.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- The entity registry. Every module registers its records here.
--
-- `kind` names the owning module ('indicator', 'cve', 'breach'). It is text
-- rather than an enum on purpose: an enum needs ALTER TYPE ... ADD VALUE to
-- extend, which defeats the point of a modular schema.
--
-- `canonical_key` is the module's normalised identity for the record.
-- Normalisation happens exactly once, in the ingest service, at write time.
-- UNIQUE (kind, canonical_key) makes deduplication a database guarantee.
CREATE TABLE entity (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    kind          text        NOT NULL,
    canonical_key text        NOT NULL,
    first_seen    timestamptz NOT NULL DEFAULT now(),
    last_seen     timestamptz NOT NULL DEFAULT now(),
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX entity_kind_canonical_key_uq ON entity (kind, canonical_key);
CREATE INDEX entity_kind_idx ON entity (kind);
CREATE INDEX entity_last_seen_idx ON entity (last_seen);

-- The graph. Modules never hold foreign keys to each other -- all cross-module
-- links live here, so a module can reference a kind it has never heard of.
--
-- Indexed in both directions: traversal asks "what points at this" as often as
-- "what does this point at".
CREATE TABLE relationship (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id  uuid        NOT NULL REFERENCES entity (id) ON DELETE CASCADE,
    target_id  uuid        NOT NULL REFERENCES entity (id) ON DELETE CASCADE,
    type       text        NOT NULL,
    confidence real,
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    metadata   jsonb
);

CREATE UNIQUE INDEX relationship_uq ON relationship (source_id, target_id, type);
CREATE INDEX relationship_source_idx ON relationship (source_id);
CREATE INDEX relationship_target_idx ON relationship (target_id);

-- Feeds and collectors. One row per configured source.
CREATE TABLE source (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        text        NOT NULL UNIQUE,
    name        text        NOT NULL,
    url         text,
    tlp         text        NOT NULL DEFAULT 'clear',
    enabled     boolean     NOT NULL DEFAULT true,
    config      jsonb,
    last_run_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX source_enabled_idx ON source (enabled);

-- "Source X reported entity Y at time T." Append-only, and by a wide margin the
-- highest-volume table in the system.
--
-- Partitioned by month from the start rather than retrofitted later: converting
-- a large table to a partitioned one means rewriting it under an ACCESS
-- EXCLUSIVE lock, and the point at which you notice you need partitioning is
-- precisely the point at which you can least afford that.
--
-- The primary key must include the partition key, hence (id, observed_at).
CREATE TABLE sighting (
    id           uuid        NOT NULL DEFAULT gen_random_uuid(),
    entity_id    uuid        NOT NULL REFERENCES entity (id) ON DELETE CASCADE,
    source_id    uuid        NOT NULL REFERENCES source (id) ON DELETE RESTRICT,
    observed_at  timestamptz NOT NULL,
    content_hash text,
    raw_ref      text,
    context      jsonb,
    PRIMARY KEY (id, observed_at)
) PARTITION BY RANGE (observed_at);

CREATE INDEX sighting_entity_observed_idx ON sighting (entity_id, observed_at);
CREATE INDEX sighting_source_observed_idx ON sighting (source_id, observed_at);

-- Safety net so an observed_at outside every provisioned partition is never
-- rejected. It is expected to stay empty: rows sitting here block creation of
-- the partition that should have held them, so `ingest maintain` warns loudly
-- when it finds any.
CREATE TABLE sighting_default PARTITION OF sighting DEFAULT;

-- Creates the monthly partition covering p_ts if it does not already exist, and
-- returns its name. Safe to call concurrently -- two workers racing on the same
-- month resolve to one CREATE and one caught duplicate_table.
-- +goose StatementBegin
CREATE FUNCTION ensure_sighting_partition(p_ts timestamptz)
RETURNS text
LANGUAGE plpgsql
AS $$
DECLARE
    v_start timestamptz := date_trunc('month', p_ts AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
    v_end   timestamptz := (date_trunc('month', p_ts AT TIME ZONE 'UTC')
                            + interval '1 month') AT TIME ZONE 'UTC';
    v_name  text        := 'sighting_' || to_char(v_start AT TIME ZONE 'UTC', 'YYYY_MM');
BEGIN
    IF to_regclass(format('public.%I', v_name)) IS NOT NULL THEN
        RETURN v_name;
    END IF;

    EXECUTE format(
        'CREATE TABLE %I PARTITION OF sighting FOR VALUES FROM (%L) TO (%L)',
        v_name, v_start, v_end);

    RETURN v_name;
EXCEPTION
    WHEN duplicate_table THEN
        RETURN v_name;
END;
$$;
-- +goose StatementEnd

-- Retention: drop whole partitions instead of DELETE. Returns the names it
-- dropped. Never touches sighting_default.
-- +goose StatementBegin
CREATE FUNCTION drop_sighting_partitions_before(p_cutoff timestamptz)
RETURNS SETOF text
LANGUAGE plpgsql
AS $$
DECLARE
    v_child record;
    v_upper timestamptz;
BEGIN
    FOR v_child IN
        SELECT c.oid, c.relname, pg_get_expr(c.relpartbound, c.oid) AS bound
        FROM pg_class c
        JOIN pg_inherits i ON i.inhrelid = c.oid
        WHERE i.inhparent = 'sighting'::regclass
          AND c.relname <> 'sighting_default'
    LOOP
        -- Bound reads: FOR VALUES FROM ('...') TO ('...')
        v_upper := (regexp_match(v_child.bound, $re$TO \('([^']+)'\)$re$))[1]::timestamptz;
        IF v_upper IS NOT NULL AND v_upper <= p_cutoff THEN
            EXECUTE format('DROP TABLE %I', v_child.relname);
            RETURN NEXT v_child.relname;
        END IF;
    END LOOP;
END;
$$;
-- +goose StatementEnd

-- +goose Down
DROP FUNCTION IF EXISTS drop_sighting_partitions_before(timestamptz);
DROP FUNCTION IF EXISTS ensure_sighting_partition(timestamptz);
DROP TABLE IF EXISTS sighting;
DROP TABLE IF EXISTS source;
DROP TABLE IF EXISTS relationship;
DROP TABLE IF EXISTS entity;
