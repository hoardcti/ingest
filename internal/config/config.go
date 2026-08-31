// Package config loads the ingest service's configuration from the
// environment.
//
// Environment only, no config file: the service runs in containers, secrets
// arrive as environment variables, and a second configuration mechanism is a
// second place for production and development to disagree.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// EnvPrefix namespaces every variable this package reads.
const EnvPrefix = "HOARDCTI_"

// Config is the fully resolved configuration.
type Config struct {
	LogLevel  string
	LogFormat string // "json" or "text"

	Database Database
	Redis    Redis
	Queue    Queue
	Archive  Archive
	Ingest   Ingest
	HTTP     HTTP
}

// Database configures the Postgres connection.
type Database struct {
	URL                 string
	MaxConns            int32
	MinConns            int32
	StatementTimeout    time.Duration
	AutoRegisterSources bool
}

// Redis configures the connection shared by the queue and the lookup cache.
type Redis struct {
	URL      string
	CacheTTL time.Duration

	// CacheEnabled turns off the write-through projection. Ingest still works;
	// lookups fall back to Postgres.
	CacheEnabled bool
}

// Queue configures the Redis Streams transport.
type Queue struct {
	Stream        string
	Group         string
	Consumer      string
	MinIdle       time.Duration
	ClaimInterval time.Duration
	MaxLen        int64

	Workers       int
	Prefetch      int
	BlockTimeout  time.Duration
	MaxDeliveries int64
}

// Archive configures the raw payload store.
type Archive struct {
	// Backend is "s3", "fs" or "none".
	Backend string

	Bucket          string
	Endpoint        string
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	UsePathStyle    bool

	// Dir is the root directory when Backend is "fs".
	Dir string
}

// Ingest configures the processing policy.
type Ingest struct {
	MaxDropRatio float64
}

// HTTP configures the intake and observability server.
type HTTP struct {
	// Addr is the listen address. Empty disables the server entirely, which is
	// a reasonable choice for a worker that only reads the queue — but it also
	// removes /metrics and the health probes.
	Addr string

	// Tokens are the bearer tokens accepted by the submission endpoint. The
	// endpoint refuses to serve if this is empty, rather than defaulting to
	// open: an unauthenticated write path into a CTI database is not a
	// development convenience.
	Tokens []string

	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	MaxBodyBytes int64
}

// Load reads the configuration from the environment and validates it.
func Load() (*Config, error) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "ingest"
	}

	c := &Config{
		LogLevel:  env("LOG_LEVEL", "info"),
		LogFormat: env("LOG_FORMAT", "json"),

		Database: Database{
			URL:                 env("DATABASE_URL", ""),
			MaxConns:            int32(envInt("DATABASE_MAX_CONNS", 16)),
			MinConns:            int32(envInt("DATABASE_MIN_CONNS", 2)),
			StatementTimeout:    envDuration("DATABASE_STATEMENT_TIMEOUT", 5*time.Minute),
			AutoRegisterSources: envBool("AUTO_REGISTER_SOURCES", false),
		},

		Redis: Redis{
			URL:          env("REDIS_URL", ""),
			CacheTTL:     envDuration("CACHE_TTL", 30*24*time.Hour),
			CacheEnabled: envBool("CACHE_ENABLED", true),
		},

		Queue: Queue{
			Stream:        env("QUEUE_STREAM", "hoardcti.envelopes"),
			Group:         env("QUEUE_GROUP", "ingest"),
			Consumer:      env("QUEUE_CONSUMER", hostname),
			MinIdle:       envDuration("QUEUE_MIN_IDLE", 5*time.Minute),
			ClaimInterval: envDuration("QUEUE_CLAIM_INTERVAL", 30*time.Second),
			MaxLen:        int64(envInt("QUEUE_MAX_LEN", 1_000_000)),
			Workers:       envInt("QUEUE_WORKERS", 4),
			Prefetch:      envInt("QUEUE_PREFETCH", 0),
			BlockTimeout:  envDuration("QUEUE_BLOCK_TIMEOUT", 5*time.Second),
			MaxDeliveries: int64(envInt("QUEUE_MAX_DELIVERIES", 5)),
		},

		Archive: Archive{
			Backend:         env("ARCHIVE_BACKEND", "none"),
			Bucket:          env("ARCHIVE_BUCKET", ""),
			Endpoint:        env("ARCHIVE_ENDPOINT", ""),
			Region:          env("ARCHIVE_REGION", "auto"),
			AccessKeyID:     env("ARCHIVE_ACCESS_KEY_ID", ""),
			SecretAccessKey: env("ARCHIVE_SECRET_ACCESS_KEY", ""),
			UsePathStyle:    envBool("ARCHIVE_USE_PATH_STYLE", false),
			Dir:             env("ARCHIVE_DIR", ""),
		},

		Ingest: Ingest{
			MaxDropRatio: envFloat("INGEST_MAX_DROP_RATIO", 0.25),
		},

		HTTP: HTTP{
			Addr:         env("HTTP_ADDR", ":8080"),
			Tokens:       envList("HTTP_TOKENS"),
			ReadTimeout:  envDuration("HTTP_READ_TIMEOUT", 30*time.Second),
			WriteTimeout: envDuration("HTTP_WRITE_TIMEOUT", 30*time.Second),
			MaxBodyBytes: int64(envInt("HTTP_MAX_BODY_BYTES", 32<<20)),
		},
	}

	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate() error {
	var problems []string

	if c.Database.URL == "" {
		problems = append(problems, EnvPrefix+"DATABASE_URL is required")
	}
	if c.Database.MaxConns < 1 {
		problems = append(problems, EnvPrefix+"DATABASE_MAX_CONNS must be at least 1")
	}
	if c.Queue.Workers >= int(c.Database.MaxConns) {
		problems = append(problems, fmt.Sprintf(
			"%sQUEUE_WORKERS (%d) must be below %sDATABASE_MAX_CONNS (%d): each worker "+
				"holds a transaction for the length of its batch, and a pool that cannot "+
				"serve them all deadlocks under load",
			EnvPrefix, c.Queue.Workers, EnvPrefix, c.Database.MaxConns))
	}
	if c.Ingest.MaxDropRatio < 0 || c.Ingest.MaxDropRatio > 1 {
		problems = append(problems, EnvPrefix+"INGEST_MAX_DROP_RATIO must be between 0 and 1")
	}

	switch strings.ToLower(c.Archive.Backend) {
	case "", "none":
		c.Archive.Backend = "none"
	case "s3", "r2":
		c.Archive.Backend = "s3"
		if c.Archive.Bucket == "" {
			problems = append(problems, EnvPrefix+"ARCHIVE_BUCKET is required when the archive backend is s3")
		}
	case "fs", "file":
		c.Archive.Backend = "fs"
		if c.Archive.Dir == "" {
			problems = append(problems, EnvPrefix+"ARCHIVE_DIR is required when the archive backend is fs")
		}
	default:
		problems = append(problems, fmt.Sprintf(
			"%sARCHIVE_BACKEND %q is not one of: none, s3, fs",
			EnvPrefix, c.Archive.Backend))
	}

	switch strings.ToLower(c.LogFormat) {
	case "json", "text":
		c.LogFormat = strings.ToLower(c.LogFormat)
	default:
		problems = append(problems, EnvPrefix+"LOG_FORMAT must be json or text")
	}

	if len(problems) > 0 {
		return fmt.Errorf("configuration invalid:\n  - %s", strings.Join(problems, "\n  - "))
	}
	return nil
}

// ErrNoRedis is returned when a command needs the transport or the cache and no
// Redis URL is configured.
var ErrNoRedis = errors.New(EnvPrefix + "REDIS_URL is not set")

func env(key, def string) string {
	if v, ok := os.LookupEnv(EnvPrefix + key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := env(key, "")
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envFloat(key string, def float64) float64 {
	v := env(key, "")
	if v == "" {
		return def
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return def
	}
	return f
}

func envBool(key string, def bool) bool {
	v := env(key, "")
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

func envDuration(key string, def time.Duration) time.Duration {
	v := env(key, "")
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

// envList splits a comma-separated variable, trimming whitespace and dropping
// empties.
func envList(key string) []string {
	v := env(key, "")
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
