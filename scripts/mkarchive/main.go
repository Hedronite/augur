// Command mkarchive writes a deterministic .tar.gz: the same inputs give the
// same bytes on any host. Entries are sorted by name, every owner is 0 with no
// user or group name, every mtime is the given epoch, modes are 0755 or 0644,
// and the gzip header carries no name or time. It exists so the release
// tarball does not depend on the tar and gzip of the machine that builds it.
//
// Usage: mkarchive OUT.tar.gz TOPDIR EPOCH DEST=SRC...
//
// Each DEST=SRC puts the file or directory tree SRC at TOPDIR/DEST. A file is
// 0755 if SRC has any execute bit, else 0644. Symbolic links are refused.
package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mkarchive:", err)
		os.Exit(1)
	}
}

type entry struct {
	name string // slash-separated, relative to the archive root; a directory ends in "/"
	src  string // empty for a directory
	mode int64
	size int64
}

func run(args []string) error {
	if len(args) < 4 {
		return errors.New("usage: mkarchive OUT.tar.gz TOPDIR EPOCH DEST=SRC [DEST=SRC ...]")
	}
	out, top := args[0], args[1]
	epoch, err := strconv.ParseInt(args[2], 10, 64)
	if err != nil || epoch < 0 {
		return fmt.Errorf("EPOCH %q is not a non-negative integer", args[2])
	}
	if top == "" || strings.ContainsAny(top, "/\\") || top == "." || top == ".." {
		return fmt.Errorf("TOPDIR %q must be a single plain directory name", top)
	}

	byName := map[string]entry{top + "/": {name: top + "/", mode: 0o755}}
	for _, spec := range args[3:] {
		dest, src, ok := strings.Cut(spec, "=")
		if !ok || dest == "" || src == "" || path.Clean(dest) != dest || strings.HasPrefix(dest, "/") || strings.HasPrefix(dest, "../") {
			return fmt.Errorf("bad entry %q: want DEST=SRC with a clean relative DEST", spec)
		}
		if err := collect(byName, top, dest, src); err != nil {
			return err
		}
	}

	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)

	f, err := os.Create(filepath.Clean(out)) //nolint:gosec // a build tool: the path is an argument from the release script
	if err != nil {
		return err
	}
	zw, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		_ = f.Close()
		return err
	}
	tw := tar.NewWriter(zw)
	mtime := time.Unix(epoch, 0).UTC()
	for _, n := range names {
		e := byName[n]
		hdr := &tar.Header{Name: e.name, Mode: e.mode, ModTime: mtime, Format: tar.FormatUSTAR}
		if e.src == "" {
			hdr.Typeflag = tar.TypeDir
		} else {
			hdr.Typeflag, hdr.Size = tar.TypeReg, e.size
		}
		if err := tw.WriteHeader(hdr); err != nil {
			_ = f.Close()
			return err
		}
		if e.src != "" {
			if err := copyFile(tw, e.src); err != nil {
				_ = f.Close()
				return err
			}
		}
	}
	if err := tw.Close(); err != nil {
		_ = f.Close()
		return err
	}
	if err := zw.Close(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// collect adds src (a file or a tree) at top/dest, and the directories above it.
func collect(byName map[string]entry, top, dest, src string) error {
	info, err := os.Lstat(src) //nolint:gosec // a build tool: the path is an argument from the release script
	if err != nil {
		return err
	}
	addParents := func(rel string) {
		for d := path.Dir(rel); d != "." && d != "/"; d = path.Dir(d) {
			n := top + "/" + d + "/"
			byName[n] = entry{name: n, mode: 0o755}
		}
	}
	add := func(rel, p string, fi fs.FileInfo) error {
		if fi.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symbolic link; refusing", p)
		}
		addParents(rel)
		if fi.IsDir() {
			n := top + "/" + rel + "/"
			byName[n] = entry{name: n, mode: 0o755}
			return nil
		}
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("%s is not a regular file", p)
		}
		mode := int64(0o644)
		if fi.Mode()&0o111 != 0 {
			mode = 0o755
		}
		n := top + "/" + rel
		byName[n] = entry{name: n, src: p, mode: mode, size: fi.Size()}
		return nil
	}
	if !info.IsDir() {
		return add(dest, src, info)
	}
	walk := func(p string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return add(dest, p, fi)
		}
		return add(path.Join(dest, filepath.ToSlash(rel)), p, fi)
	}
	return filepath.WalkDir(src, walk) //nolint:gosec // a build tool: the path is an argument from the release script
}

func copyFile(w io.Writer, src string) (err error) {
	f, err := os.Open(filepath.Clean(src))
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	_, err = io.Copy(w, f)
	return err
}
