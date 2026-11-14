package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tree(t *testing.T, mtime time.Time) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]os.FileMode{"bin/augur": 0o755, "LICENSE": 0o600, "schema/b.json": 0o664, "schema/a.json": 0o644, "schema/sub/c.json": 0o644}
	for name, mode := range files {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("content of "+name), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func build(t *testing.T, root, out string, epoch string) []byte {
	t.Helper()
	err := run([]string{out, "augur_v0", epoch,
		"schema=" + filepath.Join(root, "schema"), "LICENSE=" + filepath.Join(root, "LICENSE"), "augur=" + filepath.Join(root, "bin/augur")})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSameInputsSameBytes(t *testing.T) {
	// Two trees with different mtimes and different paths: identical archives.
	a := build(t, tree(t, time.Unix(1_000_000_000, 0)), filepath.Join(t.TempDir(), "a.tar.gz"), "1700000000")
	b := build(t, tree(t, time.Unix(1_600_000_000, 0)), filepath.Join(t.TempDir(), "b.tar.gz"), "1700000000")
	if !bytes.Equal(a, b) {
		t.Fatal("archives differ for the same content")
	}
	c := build(t, tree(t, time.Unix(1_000_000_000, 0)), filepath.Join(t.TempDir(), "c.tar.gz"), "1700000001")
	if bytes.Equal(a, c) {
		t.Fatal("the epoch did not reach the archive")
	}
}

func TestEntriesAreSortedAndNormalised(t *testing.T) {
	data := build(t, tree(t, time.Now()), filepath.Join(t.TempDir(), "x.tar.gz"), "1700000000")
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if zr.Name != "" || !zr.ModTime.IsZero() && zr.ModTime.Unix() != 0 {
		t.Fatalf("gzip header carries a name or time: %q %v", zr.Name, zr.ModTime)
	}
	tr := tar.NewReader(zr)
	var names []string
	modes := map[string]int64{}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
		modes[h.Name] = h.Mode
		if h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" || h.ModTime.Unix() != 1700000000 {
			t.Errorf("%s: uid %d gid %d uname %q gname %q mtime %v", h.Name, h.Uid, h.Gid, h.Uname, h.Gname, h.ModTime)
		}
	}
	want := []string{"augur_v0/", "augur_v0/LICENSE", "augur_v0/augur", "augur_v0/schema/", "augur_v0/schema/a.json", "augur_v0/schema/b.json", "augur_v0/schema/sub/", "augur_v0/schema/sub/c.json"}
	if len(names) != len(want) {
		t.Fatalf("entries %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("entries %v, want %v", names, want)
		}
	}
	if modes["augur_v0/augur"] != 0o755 || modes["augur_v0/LICENSE"] != 0o644 || modes["augur_v0/schema/b.json"] != 0o644 || modes["augur_v0/schema/"] != 0o755 {
		t.Fatalf("modes %v", modes)
	}
}

func TestRefusals(t *testing.T) {
	root := tree(t, time.Now())
	if err := os.Symlink(filepath.Join(root, "LICENSE"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "o.tar.gz")
	for name, args := range map[string][]string{
		"symlink":     {out, "t", "1", "link=" + filepath.Join(root, "link")},
		"bad epoch":   {out, "t", "-1", "a=" + filepath.Join(root, "LICENSE")},
		"bad top":     {out, "a/b", "1", "a=" + filepath.Join(root, "LICENSE")},
		"dest escape": {out, "t", "1", "../a=" + filepath.Join(root, "LICENSE")},
		"missing src": {out, "t", "1", "a=" + filepath.Join(root, "nope")},
		"no entries":  {out, "t", "1"},
	} {
		if err := run(args); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}
