package config

import (
	"strings"
	"testing"
)

func setEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	t.Setenv(EnvPrefix+"DATABASE_URL", "postgres://localhost/hoardcti")
	for k, v := range kv {
		t.Setenv(EnvPrefix+k, v)
	}
}

func TestLoadDefaults(t *testing.T) {
	setEnv(t, nil)

	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Queue.Stream != "hoardcti.envelopes" {
		t.Errorf("stream = %q, want the default", c.Queue.Stream)
	}
	if c.Archive.Backend != "none" {
		t.Errorf("archive backend = %q, want none", c.Archive.Backend)
	}
	if c.Database.AutoRegisterSources {
		t.Error("source auto-registration defaults on; an unknown slug is usually a typo")
	}
	if c.Queue.Consumer == "" {
		t.Error("consumer name is empty; it must default to something stable across restarts")
	}
}

func TestLoadRequiresDatabaseURL(t *testing.T) {
	t.Setenv(EnvPrefix+"DATABASE_URL", "")

	_, err := Load()
	if err == nil {
		t.Fatal("Load succeeded with no database URL")
	}
	if !strings.Contains(err.Error(), "DATABASE_URL") {
		t.Errorf("error = %v, want it to name DATABASE_URL", err)
	}
}

// Each worker holds a transaction for the length of its batch. A pool that
// cannot serve them all deadlocks under load, so the mistake is caught at
// startup rather than at peak traffic.
func TestLoadRejectsMoreWorkersThanConnections(t *testing.T) {
	setEnv(t, map[string]string{
		"QUEUE_WORKERS":      "16",
		"DATABASE_MAX_CONNS": "8",
	})

	_, err := Load()
	if err == nil {
		t.Fatal("Load accepted more workers than connections")
	}
	if !strings.Contains(err.Error(), "QUEUE_WORKERS") {
		t.Errorf("error = %v, want it to name QUEUE_WORKERS", err)
	}
}

func TestLoadValidatesArchiveBackend(t *testing.T) {
	setEnv(t, map[string]string{"ARCHIVE_BACKEND": "s3"})
	if _, err := Load(); err == nil {
		t.Error("s3 backend accepted with no bucket")
	}

	setEnv(t, map[string]string{"ARCHIVE_BACKEND": "fs"})
	if _, err := Load(); err == nil {
		t.Error("fs backend accepted with no directory")
	}

	// r2 is an alias for s3, because that is what people will type.
	setEnv(t, map[string]string{"ARCHIVE_BACKEND": "r2", "ARCHIVE_BUCKET": "hoardcti-raw"})
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Archive.Backend != "s3" {
		t.Errorf("backend = %q, want r2 normalised to s3", c.Archive.Backend)
	}

	setEnv(t, map[string]string{"ARCHIVE_BACKEND": "gcs"})
	if _, err := Load(); err == nil {
		t.Error("an unknown archive backend was accepted")
	}
}

func TestLoadReportsEveryProblemAtOnce(t *testing.T) {
	t.Setenv(EnvPrefix+"DATABASE_URL", "")
	t.Setenv(EnvPrefix+"ARCHIVE_BACKEND", "gcs")
	t.Setenv(EnvPrefix+"LOG_FORMAT", "xml")

	_, err := Load()
	if err == nil {
		t.Fatal("Load succeeded")
	}
	for _, want := range []string{"DATABASE_URL", "ARCHIVE_BACKEND", "LOG_FORMAT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %s:\n%v", want, err)
		}
	}
}

func TestEnvList(t *testing.T) {
	t.Setenv(EnvPrefix+"HTTP_TOKENS", " a , b ,, c ")
	got := envList("HTTP_TOKENS")
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("envList = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("envList[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
