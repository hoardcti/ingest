package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// sourceCacheTTL bounds how long a stale `enabled` flag can keep flowing. A
// source switched off in the database stops being accepted within this window
// without anyone restarting the ingest service.
const sourceCacheTTL = 60 * time.Second

// Source is a configured feed or collector.
type Source struct {
	ID      pgtype.UUID
	Slug    string
	Name    string
	Enabled bool
}

type sourceCache struct {
	mu sync.RWMutex
	m  map[string]cachedSource
}

type cachedSource struct {
	src Source
	at  time.Time
}

func newSourceCache() *sourceCache {
	return &sourceCache{m: make(map[string]cachedSource)}
}

func (c *sourceCache) get(slug string, now time.Time) (Source, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.m[slug]
	if !ok || now.Sub(e.at) > sourceCacheTTL {
		return Source{}, false
	}
	return e.src, true
}

func (c *sourceCache) put(src Source, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[src.Slug] = cachedSource{src: src, at: now}
}

func (c *sourceCache) forget(slug string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, slug)
}

// ResolveSource maps a source slug to its row, creating it if
// AutoRegisterSources is set. Results are cached briefly; every envelope
// carries a slug and hitting the database for each one would be pure waste.
func (s *Store) ResolveSource(ctx context.Context, slug string) (Source, error) {
	now := time.Now()
	if src, ok := s.sources.get(slug, now); ok {
		if !src.Enabled {
			return Source{}, fmt.Errorf("%w: %s", ErrSourceDisabled, slug)
		}
		return src, nil
	}

	src, err := s.lookupSource(ctx, slug)
	switch {
	case err == nil:
	case errors.Is(err, pgx.ErrNoRows) && s.opts.AutoRegisterSources:
		src, err = s.registerSource(ctx, slug)
		if err != nil {
			return Source{}, err
		}
		s.log.Info("registered new source", "slug", slug, "source_id", src.ID.String())
	case errors.Is(err, pgx.ErrNoRows):
		return Source{}, fmt.Errorf("%w: %q is not configured", ErrUnknownSource, slug)
	default:
		return Source{}, err
	}

	s.sources.put(src, now)
	if !src.Enabled {
		return Source{}, fmt.Errorf("%w: %s", ErrSourceDisabled, slug)
	}
	return src, nil
}

func (s *Store) lookupSource(ctx context.Context, slug string) (Source, error) {
	var src Source
	err := s.pool.QueryRow(ctx,
		`SELECT id, slug, name, enabled FROM source WHERE slug = $1`, slug,
	).Scan(&src.ID, &src.Slug, &src.Name, &src.Enabled)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Source{}, err
		}
		return Source{}, fmt.Errorf("look up source %q: %w", slug, err)
	}
	return src, nil
}

func (s *Store) registerSource(ctx context.Context, slug string) (Source, error) {
	var src Source
	// ON CONFLICT rather than a bare INSERT: two workers can meet the same new
	// source in the same instant.
	err := s.pool.QueryRow(ctx, `
		INSERT INTO source (slug, name)
		VALUES ($1, $1)
		ON CONFLICT (slug) DO UPDATE SET slug = EXCLUDED.slug
		RETURNING id, slug, name, enabled`, slug,
	).Scan(&src.ID, &src.Slug, &src.Name, &src.Enabled)
	if err != nil {
		return Source{}, fmt.Errorf("auto-register source %q: %w", slug, err)
	}
	return src, nil
}

// UpsertSource creates or updates a source definition. Used by
// `ingest source add`, which is how sources are meant to arrive in production.
func (s *Store) UpsertSource(ctx context.Context, slug, name, url, tlp string, enabled bool) (Source, error) {
	if name == "" {
		name = slug
	}
	if tlp == "" {
		tlp = "clear"
	}
	var src Source
	err := s.pool.QueryRow(ctx, `
		INSERT INTO source (slug, name, url, tlp, enabled)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5)
		ON CONFLICT (slug) DO UPDATE SET
			name    = EXCLUDED.name,
			url     = COALESCE(EXCLUDED.url, source.url),
			tlp     = EXCLUDED.tlp,
			enabled = EXCLUDED.enabled
		RETURNING id, slug, name, enabled`,
		slug, name, url, tlp, enabled,
	).Scan(&src.ID, &src.Slug, &src.Name, &src.Enabled)
	if err != nil {
		return Source{}, fmt.Errorf("upsert source %q: %w", slug, err)
	}
	s.sources.forget(slug)
	return src, nil
}

// ListSources returns every configured source, newest last.
func (s *Store) ListSources(ctx context.Context) ([]Source, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, slug, name, enabled FROM source ORDER BY slug`)
	if err != nil {
		return nil, fmt.Errorf("list sources: %w", err)
	}
	defer rows.Close()

	var out []Source
	for rows.Next() {
		var src Source
		if err := rows.Scan(&src.ID, &src.Slug, &src.Name, &src.Enabled); err != nil {
			return nil, fmt.Errorf("scan source: %w", err)
		}
		out = append(out, src)
	}
	return out, rows.Err()
}
