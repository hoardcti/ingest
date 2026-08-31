// Command ingest is the HoardCTI ingest service: the single process that
// writes to the CTI database.
//
// Collectors — in Go, Python, TypeScript, or a declarative feed manifest —
// produce envelopes and publish them to a queue. This binary consumes them,
// archives the raw payload, canonicalises every value exactly once, writes one
// transaction per envelope, and projects the result into the indicator lookup
// cache.
//
//	ingest migrate up          apply the schema
//	ingest source add …        register a feed
//	ingest serve               consume the queue
//	ingest maintain            provision partitions, apply retention
//	ingest submit file.json    publish an envelope to the queue
//	ingest load file.json      write an envelope directly, bypassing the queue
//	ingest validate file.json  check an envelope against the contract
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/hoardcti/ingest/internal/archive"
	"github.com/hoardcti/ingest/internal/cache"
	"github.com/hoardcti/ingest/internal/config"
	"github.com/hoardcti/ingest/internal/store"
)

const usage = `ingest — the HoardCTI ingest service

Usage:
  ingest <command> [flags]

Commands:
  serve                    Consume envelopes from the queue and write them
  migrate up               Apply all pending migrations
  migrate up-to <version>  Apply migrations up to and including a version
  migrate down             Roll back the most recent migration
  migrate down-to <ver>    Roll back to and including a version
  migrate status           List migrations and whether they are applied
  migrate version          Print the current schema version
  source add <slug>        Register or update a feed
  source list              List configured feeds
  maintain                 Provision sighting partitions and apply retention
  submit <file>            Publish an envelope file to the queue
  load <file>              Write an envelope file directly, bypassing the queue
  validate <file>          Check an envelope against the contract (no database)
  version                  Print build information

Configuration is read from the environment; every variable is prefixed
HOARDCTI_. See README.md for the full list. The only required one is
HOARDCTI_DATABASE_URL.
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "ingest: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		return errors.New("no command given")
	}

	cmd, args := os.Args[1], os.Args[2:]

	// Commands that need neither configuration nor a database.
	switch cmd {
	case "help", "-h", "--help":
		fmt.Print(usage)
		return nil
	case "version", "--version":
		fmt.Println(versionString())
		return nil
	case "validate":
		return cmdValidate(args)
	}

	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := newLogger(cfg)
	slog.SetDefault(log)

	switch cmd {
	case "serve":
		return cmdServe(ctx, cfg, log, args)
	case "migrate":
		return cmdMigrate(ctx, cfg, log, args)
	case "source":
		return cmdSource(ctx, cfg, log, args)
	case "maintain":
		return cmdMaintain(ctx, cfg, log, args)
	case "submit":
		return cmdSubmit(ctx, cfg, log, args)
	case "load":
		return cmdLoad(ctx, cfg, log, args)
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func newLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	if err := level.UnmarshalText([]byte(cfg.LogLevel)); err != nil {
		level = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: level}

	var h slog.Handler
	if cfg.LogFormat == "text" {
		h = slog.NewTextHandler(os.Stderr, opts)
	} else {
		h = slog.NewJSONHandler(os.Stderr, opts)
	}
	return slog.New(h)
}

// openStore connects to Postgres and refuses to continue against a schema this
// build does not recognise.
//
// Checking rather than migrating: a service that migrates on boot turns a
// rolling deploy into a race between replicas over an ACCESS EXCLUSIVE lock,
// and makes a rollback impossible because the old binary is already gone.
func openStore(ctx context.Context, cfg *config.Config, log *slog.Logger, checkSchema bool) (*store.Store, error) {
	st, err := store.Open(ctx, store.Options{
		DSN:                 cfg.Database.URL,
		MaxConns:            cfg.Database.MaxConns,
		MinConns:            cfg.Database.MinConns,
		StatementTimeout:    cfg.Database.StatementTimeout,
		AutoRegisterSources: cfg.Database.AutoRegisterSources,
		Logger:              log,
	})
	if err != nil {
		return nil, err
	}

	if checkSchema {
		m, err := store.NewMigrator(st, log)
		if err != nil {
			st.Close()
			return nil, err
		}
		defer m.Close()

		pending, err := m.HasPending(ctx)
		if err != nil {
			st.Close()
			return nil, err
		}
		if pending {
			st.Close()
			return nil, errors.New(
				"the database has unapplied migrations; run `ingest migrate up` " +
					"before starting the service")
		}
	}
	return st, nil
}

func openRedis(cfg *config.Config) (redis.UniversalClient, error) {
	if cfg.Redis.URL == "" {
		return nil, config.ErrNoRedis
	}
	opts, err := redis.ParseURL(cfg.Redis.URL)
	if err != nil {
		return nil, fmt.Errorf("parse %sREDIS_URL: %w", config.EnvPrefix, err)
	}
	return redis.NewClient(opts), nil
}

func openArchive(ctx context.Context, cfg *config.Config) (archive.Archiver, error) {
	switch cfg.Archive.Backend {
	case "s3":
		return archive.NewS3(ctx, archive.S3Options{
			Bucket:          cfg.Archive.Bucket,
			Endpoint:        cfg.Archive.Endpoint,
			Region:          cfg.Archive.Region,
			AccessKeyID:     cfg.Archive.AccessKeyID,
			SecretAccessKey: cfg.Archive.SecretAccessKey,
			UsePathStyle:    cfg.Archive.UsePathStyle,
		})
	case "fs":
		return archive.NewFS(cfg.Archive.Dir)
	default:
		return archive.Noop{}, nil
	}
}

func openCache(cfg *config.Config, client redis.UniversalClient) cache.Cache {
	if !cfg.Redis.CacheEnabled || client == nil {
		return cache.Noop{}
	}
	return cache.NewRedis(client, redactedRedisAddr(cfg.Redis.URL))
}

// redactedRedisAddr strips any password from a Redis URL so the address can go
// in a log line.
func redactedRedisAddr(url string) string {
	if i := strings.Index(url, "@"); i >= 0 {
		if j := strings.Index(url, "://"); j >= 0 && j < i {
			return url[:j+3] + "***@" + url[i+1:]
		}
	}
	return strings.TrimPrefix(strings.TrimPrefix(url, "redis://"), "rediss://")
}

func versionString() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "ingest (unknown build)"
	}
	var revision, modified, when string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				modified = " (dirty)"
			}
		case "vcs.time":
			when = s.Value
		}
	}
	if revision == "" {
		return fmt.Sprintf("ingest (%s)", info.GoVersion)
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	return fmt.Sprintf("ingest %s%s built %s with %s", revision, modified, when, info.GoVersion)
}

// shortDuration formats a duration for human-readable command output.
func shortDuration(d time.Duration) string {
	return d.Round(time.Millisecond).String()
}

// parseFlags parses args, allowing flags and positional arguments to be mixed
// in any order, and returns the positional ones.
//
// The standard library stops parsing flags at the first non-flag argument, so
// `ingest source add my-feed -name "My Feed"` would silently ignore -name and
// register the feed under its slug. Since that is the order everyone types, the
// tool accepts it: parse, take one positional, parse what is left, repeat.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}
