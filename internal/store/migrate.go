package store

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/lock"

	"github.com/hoardcti/ingest/db"
)

// MigrationStatus is one migration and whether it has been applied.
type MigrationStatus struct {
	Version int64
	Source  string
	Applied bool
}

// Migrator applies the embedded schema migrations.
//
// It runs through database/sql, which is what goose speaks, over the same pgx
// pool the rest of the service uses — pgx's stdlib adapter wraps the pool as a
// *sql.DB, so there is one pool and one set of connection settings, not two.
type Migrator struct {
	provider *goose.Provider
	closeDB  func() error
}

// NewMigrator builds a migrator over an open store.
func NewMigrator(s *Store, logger *slog.Logger) (*Migrator, error) {
	if logger == nil {
		logger = slog.Default()
	}

	fsys, err := fs.Sub(db.Migrations, db.MigrationsDir)
	if err != nil {
		return nil, fmt.Errorf("open embedded migrations: %w", err)
	}

	// A session-scoped advisory lock, so that starting several replicas at once
	// is safe: one applies the migrations and the rest wait, then find nothing
	// to do. Without it, concurrent `migrate up` calls race on DDL and one of
	// them fails in a way that looks like a corrupt schema.
	locker, err := lock.NewPostgresSessionLocker()
	if err != nil {
		return nil, fmt.Errorf("create migration locker: %w", err)
	}

	sqlDB := stdlib.OpenDBFromPool(s.pool)
	provider, err := goose.NewProvider(goose.DialectPostgres, sqlDB, fsys,
		goose.WithSessionLocker(locker),
		goose.WithSlog(logger),
	)
	if err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("create migration provider: %w", err)
	}

	return &Migrator{provider: provider, closeDB: sqlDB.Close}, nil
}

// Close releases the database/sql handle. The underlying pgx pool is untouched.
func (m *Migrator) Close() error { return m.closeDB() }

// Up applies every pending migration and returns the versions it applied.
func (m *Migrator) Up(ctx context.Context) ([]int64, error) {
	results, err := m.provider.Up(ctx)
	return versions(results), wrapMigrationErr("apply migrations", err)
}

// UpTo applies pending migrations up to and including version.
func (m *Migrator) UpTo(ctx context.Context, version int64) ([]int64, error) {
	results, err := m.provider.UpTo(ctx, version)
	return versions(results), wrapMigrationErr("apply migrations", err)
}

// Down rolls back the most recently applied migration.
func (m *Migrator) Down(ctx context.Context) (int64, error) {
	result, err := m.provider.Down(ctx)
	if err != nil {
		return 0, wrapMigrationErr("roll back migration", err)
	}
	return result.Source.Version, nil
}

// DownTo rolls back to and including version. Passing 0 unwinds everything.
func (m *Migrator) DownTo(ctx context.Context, version int64) ([]int64, error) {
	results, err := m.provider.DownTo(ctx, version)
	return versions(results), wrapMigrationErr("roll back migrations", err)
}

// Version reports the schema version currently recorded in the database.
func (m *Migrator) Version(ctx context.Context) (int64, error) {
	v, err := m.provider.GetDBVersion(ctx)
	return v, wrapMigrationErr("read schema version", err)
}

// Status lists every known migration and whether it has been applied.
func (m *Migrator) Status(ctx context.Context) ([]MigrationStatus, error) {
	st, err := m.provider.Status(ctx)
	if err != nil {
		return nil, wrapMigrationErr("read migration status", err)
	}
	out := make([]MigrationStatus, 0, len(st))
	for _, s := range st {
		out = append(out, MigrationStatus{
			Version: s.Source.Version,
			Source:  s.Source.Path,
			Applied: s.State == goose.StateApplied,
		})
	}
	return out, nil
}

// HasPending reports whether any migration is waiting to be applied. The
// service checks this at startup and refuses to run against a schema it does
// not recognise, rather than failing on the first query that needs the new
// column.
func (m *Migrator) HasPending(ctx context.Context) (bool, error) {
	pending, err := m.provider.HasPending(ctx)
	return pending, wrapMigrationErr("check for pending migrations", err)
}

func versions(results []*goose.MigrationResult) []int64 {
	out := make([]int64, 0, len(results))
	for _, r := range results {
		out = append(out, r.Source.Version)
	}
	return out
}

func wrapMigrationErr(what string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", what, err)
}
