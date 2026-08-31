// Package archive stores untouched upstream payloads, keyed by content hash.
//
// This is the cheapest insurance in the design and the step most often skipped.
// Parsers improve, feeds change format without telling anyone, and you will
// want to reprocess months of history without re-scraping — which for a good
// proportion of CTI sources is not possible at all, because the data is gone.
//
// Content-hash keying makes writes idempotent and gives deduplication for free:
// a daily blocklist that has not changed since yesterday is the same object.
package archive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// ErrNotFound is returned when a reference does not resolve to a stored object.
var ErrNotFound = errors.New("archived payload not found")

// Archiver stores and retrieves raw payloads.
type Archiver interface {
	// Put stores data under its content hash and returns a reference to it.
	// Storing the same bytes twice returns the same reference and is not an
	// error.
	Put(ctx context.Context, data []byte, mediaType string) (ref string, err error)

	// Get retrieves a previously stored payload.
	Get(ctx context.Context, ref string) ([]byte, error)

	// Name identifies the backend in logs and health output.
	Name() string
}

// HashPrefix is the algorithm label used in content hashes and object keys.
const HashPrefix = "sha256:"

// Hash returns the content hash of data in the "sha256:<hex>" form the envelope
// contract uses.
func Hash(data []byte) string {
	sum := sha256.Sum256(data)
	return HashPrefix + hex.EncodeToString(sum[:])
}

// Key derives the object key for a content hash.
//
// The two-level fan-out is not for correctness — object stores are flat — but
// for every tool that lists them. A single prefix holding ten million keys is
// unbrowsable and slow to paginate; ab/cd/ keeps any one listing small.
func Key(contentHash string) (string, error) {
	h := strings.TrimPrefix(contentHash, HashPrefix)
	if len(h) != 64 {
		return "", fmt.Errorf("content hash %q is not a sha256 digest", contentHash)
	}
	for _, r := range h {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return "", fmt.Errorf("content hash %q is not lowercase hex", contentHash)
		}
	}
	return "raw/sha256/" + h[0:2] + "/" + h[2:4] + "/" + h, nil
}

// Noop discards payloads and returns an empty reference. It is what runs when
// no archive is configured — which is a legitimate choice for a development
// machine and a bad one for anything you would miss.
type Noop struct{}

// Put implements [Archiver].
func (Noop) Put(context.Context, []byte, string) (string, error) { return "", nil }

// Get implements [Archiver].
func (Noop) Get(context.Context, string) ([]byte, error) { return nil, ErrNotFound }

// Name implements [Archiver].
func (Noop) Name() string { return "none" }

// seenCache remembers hashes this process has already stored, so a feed that
// ships the same unchanged payload every hour costs one round trip on the first
// delivery and none afterwards.
//
// It is intentionally a plain bounded set rather than an LRU: entries are all
// equally useful, the working set is "payloads seen since restart", and the
// consequence of evicting the wrong one is a single redundant HEAD request.
type seenCache struct {
	mu    sync.Mutex
	m     map[string]struct{}
	limit int
}

func newSeenCache(limit int) *seenCache {
	if limit <= 0 {
		limit = 8192
	}
	return &seenCache{m: make(map[string]struct{}), limit: limit}
}

func (c *seenCache) has(k string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.m[k]
	return ok
}

func (c *seenCache) add(k string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) >= c.limit {
		// Drop an arbitrary slice of the set rather than clearing it entirely,
		// so a full cache does not cause a thundering herd of HEAD requests.
		n := c.limit / 4
		for key := range c.m {
			delete(c.m, key)
			if n--; n <= 0 {
				break
			}
		}
	}
	c.m[k] = struct{}{}
}
