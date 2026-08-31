package archive

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestHashAndKey(t *testing.T) {
	// The empty string's SHA-256 is a well-known constant, so this pins the
	// hash format rather than just checking it against itself.
	const emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	if got := Hash(nil); got != HashPrefix+emptySHA256 {
		t.Errorf("Hash(nil) = %q, want %q", got, HashPrefix+emptySHA256)
	}

	key, err := Key(Hash(nil))
	if err != nil {
		t.Fatalf("Key: %v", err)
	}
	// Two levels of fan-out so no single prefix ever holds millions of keys.
	want := "raw/sha256/e3/b0/" + emptySHA256
	if key != want {
		t.Errorf("Key = %q, want %q", key, want)
	}

	// A bare digest with no prefix is accepted; anything else is not.
	if _, err := Key(emptySHA256); err != nil {
		t.Errorf("Key of a bare digest: %v", err)
	}
	for _, bad := range []string{"", "sha256:short", "md5:" + emptySHA256, strings.ToUpper(emptySHA256)} {
		if _, err := Key(bad); err == nil {
			t.Errorf("Key(%q) succeeded, want an error", bad)
		}
	}
}

func TestFSRoundTrip(t *testing.T) {
	a, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatalf("NewFS: %v", err)
	}
	ctx := context.Background()

	payload := []byte("0.0.0.0 evil.example\n0.0.0.0 worse.example\n")
	ref, err := a.Put(ctx, payload, "text/plain")
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	got, err := a.Get(ctx, ref)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("Get returned %q, want the original payload", got)
	}
}

// Content-hash keying is what makes archival idempotent: a daily blocklist that
// has not changed since yesterday must be the same object, not a second copy.
func TestFSPutIsIdempotent(t *testing.T) {
	a, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatalf("NewFS: %v", err)
	}
	ctx := context.Background()
	payload := []byte("unchanged")

	first, err := a.Put(ctx, payload, "text/plain")
	if err != nil {
		t.Fatalf("first Put: %v", err)
	}
	second, err := a.Put(ctx, payload, "text/plain")
	if err != nil {
		t.Fatalf("second Put: %v", err)
	}
	if first != second {
		t.Errorf("the same bytes produced two references: %q and %q", first, second)
	}

	other, err := a.Put(ctx, []byte("changed"), "text/plain")
	if err != nil {
		t.Fatalf("Put of different bytes: %v", err)
	}
	if other == first {
		t.Error("different bytes produced the same reference")
	}
}

func TestFSGetMissing(t *testing.T) {
	a, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatalf("NewFS: %v", err)
	}
	_, err = a.Get(context.Background(), "file://raw/sha256/00/00/"+strings.Repeat("0", 64))
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("Get of a missing object = %v, want ErrNotFound", err)
	}
}

// References come out of the database, and the database is fed by collectors.
// A reference must not be able to read outside the archive root.
func TestFSGetRejectsTraversal(t *testing.T) {
	a, err := NewFS(t.TempDir())
	if err != nil {
		t.Fatalf("NewFS: %v", err)
	}
	for _, ref := range []string{
		"file://../../../etc/passwd",
		"../../secrets",
	} {
		if _, err := a.Get(context.Background(), ref); err == nil {
			t.Errorf("Get(%q) succeeded; path traversal is not being rejected", ref)
		}
	}
}

func TestNoop(t *testing.T) {
	ctx := context.Background()
	ref, err := Noop{}.Put(ctx, []byte("x"), "text/plain")
	if err != nil || ref != "" {
		t.Errorf("Noop.Put = (%q, %v), want an empty reference and no error", ref, err)
	}
	if _, err := (Noop{}).Get(ctx, "anything"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Noop.Get = %v, want ErrNotFound", err)
	}
}

// The set drops entries when full rather than growing without bound, but must
// still remember what it was just told.
func TestSeenCacheBounded(t *testing.T) {
	c := newSeenCache(8)
	for i := range 40 {
		c.add(string(rune('a' + i)))
	}
	if len(c.m) > 8 {
		t.Errorf("cache holds %d entries, over its limit of 8", len(c.m))
	}
	c.add("recent")
	if !c.has("recent") {
		t.Error("the most recently added key is missing")
	}
}
