package serve

import (
	"fmt"
	"os"
	"path/filepath"
)

// FilePerm is the mode of the verdict file.
const FilePerm = 0o644

// WriteAtomic replaces path with data so that a reader never sees a partial
// file: temp file in the same directory, write, fsync, chmod, rename, then
// fsync the directory. On any failure the temp file is removed and the
// previous file is untouched.
func WriteAtomic(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, tmpPrefix+"*"+tmpSuffix)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err = f.Chmod(FilePerm); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("fsync temp file: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err = os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	// The rename has happened; a directory fsync failure is reported but the
	// new file is already in place.
	d, derr := os.Open(dir) //nolint:gosec // the directory of the operator's --out
	if derr != nil {
		return fmt.Errorf("open directory: %w", derr)
	}
	defer func() { _ = d.Close() }()
	if serr := d.Sync(); serr != nil {
		return fmt.Errorf("fsync directory: %w", serr)
	}
	return nil
}

// CleanStrayTemp removes temp files a crashed run left in dir. It matches only
// regular files named exactly .augur-*.tmp and never follows a symlink.
func CleanStrayTemp(dir string) (removed int, err error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		ok, merr := filepath.Match(tmpPrefix+"*"+tmpSuffix, e.Name())
		if merr != nil || !ok || !e.Type().IsRegular() {
			continue
		}
		if rerr := os.Remove(filepath.Join(dir, e.Name())); rerr == nil {
			removed++
		}
	}
	return removed, nil
}
