package archive

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// FS is an [Archiver] backed by a local directory. It exists so that the
// archive step is exercised in development and in tests rather than being
// stubbed out — the bug you want to catch is "we never actually wrote the raw
// payload", and a no-op archive hides exactly that.
type FS struct {
	root string
	seen *seenCache
}

// NewFS creates a filesystem archive rooted at dir.
func NewFS(dir string) (*FS, error) {
	if dir == "" {
		return nil, errors.New("archive: directory is required")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("archive: resolve %q: %w", dir, err)
	}
	if err := os.MkdirAll(abs, 0o750); err != nil {
		return nil, fmt.Errorf("archive: create %q: %w", abs, err)
	}
	return &FS{root: abs, seen: newSeenCache(8192)}, nil
}

// Name implements [Archiver].
func (a *FS) Name() string { return "file://" + a.root }

// Put implements [Archiver].
func (a *FS) Put(_ context.Context, data []byte, _ string) (string, error) {
	hash := Hash(data)
	key, err := Key(hash)
	if err != nil {
		return "", err
	}
	ref := "file://" + key

	if a.seen.has(key) {
		return ref, nil
	}

	path := filepath.Join(a.root, filepath.FromSlash(key))
	if _, err := os.Stat(path); err == nil {
		a.seen.add(key)
		return ref, nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("archive: stat %s: %w", path, err)
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return "", fmt.Errorf("archive: create directory for %s: %w", key, err)
	}
	// Write to a temporary file and rename, so a crash mid-write cannot leave a
	// truncated payload sitting under a hash that claims to describe it.
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return "", fmt.Errorf("archive: create temp file for %s: %w", key, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename has succeeded

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return "", fmt.Errorf("archive: write %s: %w", key, err)
	}
	if err := tmp.Close(); err != nil {
		return "", fmt.Errorf("archive: close %s: %w", key, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", fmt.Errorf("archive: publish %s: %w", key, err)
	}

	a.seen.add(key)
	return ref, nil
}

// Get implements [Archiver].
func (a *FS) Get(_ context.Context, ref string) ([]byte, error) {
	key := strings.TrimPrefix(ref, "file://")
	if key == "" {
		return nil, errors.New("archive: empty reference")
	}
	// Reject anything that escapes the archive root. References come from the
	// database, and the database is fed by collectors.
	clean := filepath.Clean(filepath.FromSlash(key))
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return nil, fmt.Errorf("archive: reference %q escapes the archive root", ref)
	}

	data, err := os.ReadFile(filepath.Join(a.root, clean))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, ref)
		}
		return nil, fmt.Errorf("archive: read %s: %w", ref, err)
	}
	return data, nil
}
