// Package store owns every write to Postgres.
//
// Exactly one process writes to this database, and this is the package it does
// it through. That is not an aesthetic preference: canonicalisation and
// deduplication are only correct if they happen in one place, and a second
// writer with its own idea of how to normalise a hash would silently defeat the
// UNIQUE (kind, canonical_key) constraint the whole system rests on.
package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Options configure a [Store].
type Options struct {
	// DSN is the Postgres connection string.
	DSN string

	// MaxConns caps the pool. Zero uses pgx's default (max(4, NumCPU)).
	MaxConns int32

	// MinConns keeps this many connections warm. Ingest is bursty and
	// connection setup is not free.
	MinConns int32

	// ApplicationName appears in pg_stat_activity, which is where you will be
	// looking when ingest is the thing holding a lock.
	ApplicationName string

	// StatementTimeout bounds any single statement. A batch that has gone
	// pathological should fail loudly rather than block the write path.
	StatementTimeout time.Duration

	// AutoRegisterSources creates a source row on first sight instead of
	// rejecting the envelope. Convenient in development, off in production
	// where an unknown source slug usually means a typo.
	AutoRegisterSources bool

	Logger *slog.Logger
}

func (o *Options) setDefaults() {
	if o.ApplicationName == "" {
		o.ApplicationName = "hoardcti-ingest"
	}
	if o.StatementTimeout == 0 {
		o.StatementTimeout = 5 * time.Minute
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
}

// Store is the Postgres writer. It is safe for concurrent use.
type Store struct {
	pool *pgxpool.Pool
	opts Options
	log  *slog.Logger

	sources    *sourceCache
	partitions *partitionCache
}

// Open connects to Postgres and verifies the connection.
//
// It does not run migrations — that is `ingest migrate up`, a deliberate
// separate step. A service that migrates on boot turns a rolling deploy into a
// race between replicas over an ACCESS EXCLUSIVE lock.
func Open(ctx context.Context, opts Options) (*Store, error) {
	opts.setDefaults()

	cfg, err := pgxpool.ParseConfig(opts.DSN)
	if err != nil {
		return nil, fmt.Errorf("parse database DSN: %w", err)
	}
	if opts.MaxConns > 0 {
		cfg.MaxConns = opts.MaxConns
	}
	if opts.MinConns > 0 {
		cfg.MinConns = opts.MinConns
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = opts.ApplicationName
	cfg.ConnConfig.RuntimeParams["statement_timeout"] =
		fmt.Sprintf("%d", opts.StatementTimeout.Milliseconds())

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create connection pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &Store{
		pool:       pool,
		opts:       opts,
		log:        opts.Logger,
		sources:    newSourceCache(),
		partitions: newPartitionCache(),
	}, nil
}

// Pool exposes the underlying pool. Used by the migration runner, which needs a
// database/sql handle, and by read-side tooling.
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Close releases every connection.
func (s *Store) Close() { s.pool.Close() }

// Ping checks the database is reachable. Used by the readiness probe.
func (s *Store) Ping(ctx context.Context) error {
	return s.pool.Ping(ctx)
}

// inTx runs fn inside a transaction, rolling back on error or panic.
func (s *Store) inTx(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() {
		// Rollback after a successful Commit is a no-op that returns
		// ErrTxClosed, so this is safe unconditionally.
		_ = tx.Rollback(context.WithoutCancel(ctx))
	}()

	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// ErrSourceDisabled is returned when an envelope arrives from a source that has
// been switched off. It is not retryable.
var ErrSourceDisabled = errors.New("source is disabled")

// ErrUnknownSource is returned when an envelope names a source slug that has no
// row in the source table and auto-registration is off. It is not retryable —
// almost always a typo in a collector's configuration.
var ErrUnknownSource = errors.New("unknown source")
