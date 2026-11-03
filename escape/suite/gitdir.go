// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// A repository the guest writes by hand: the guest has no git, so the probe
// lays .git down itself in the formats git reads, and which git's own tools
// would refuse to make. Loose objects are zlib streams of "<kind> <size>\0"
// and the content, named by the SHA-1 of that. A tree is entries of
// "<mode> <name>\0" and a raw id, in git's order. A commit names its tree.
// The index is version 2: a header, entries with no stat data, a checksum.

// repo is a work tree whose .git the probe writes.
type repo struct{ dir string }

// entry is one tree or index entry: a mode as git writes it in a tree
// ("100644", "100755", "120000", "40000", "160000"), a name, a hex id.
type entry struct{ mode, name, id string }

// create removes any .git in the work tree and writes an empty repository:
// HEAD on main, a config of the core section with extra lines after
// repositoryformatversion and filemode, and the two directories git looks
// for. Nothing else: no template, no hooks.
func (r repo) create(extra string) error {
	g := filepath.Join(r.dir, ".git")
	if err := os.RemoveAll(g); err != nil {
		return err
	}
	for _, d := range []string{"objects", filepath.Join("refs", "heads")} {
		if err := os.MkdirAll(filepath.Join(g, d), 0o755); err != nil {
			return err
		}
	}
	config := "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n" + extra
	return errors.Join(os.WriteFile(filepath.Join(g, "HEAD"), []byte("ref: refs/heads/main\n"), 0o644),
		os.WriteFile(filepath.Join(g, "config"), []byte(config), 0o644))
}

// object writes one loose object and returns its hex id.
func (r repo) object(kind string, content []byte) (string, error) {
	raw := append(fmt.Appendf(nil, "%s %d\x00", kind, len(content)), content...)
	sum := sha1.Sum(raw)
	id := hex.EncodeToString(sum[:])
	dir := filepath.Join(r.dir, ".git", "objects", id[:2])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	w.Write(raw)
	if err := w.Close(); err != nil {
		return "", err
	}
	return id, os.WriteFile(filepath.Join(dir, id[2:]), z.Bytes(), 0o444)
}

// tree writes a tree of the entries, in git's order: by name, a subtree's
// name taken with a "/" after it. Any name goes: "..", ".git", a duplicate.
func (r repo) tree(entries ...entry) (string, error) {
	key := func(e entry) string {
		if e.mode == "40000" {
			return e.name + "/"
		}
		return e.name
	}
	slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(key(a), key(b)) })
	var b []byte
	for _, e := range entries {
		id, err := hex.DecodeString(e.id)
		if err != nil || len(id) != 20 {
			return "", fmt.Errorf("tree entry %s: bad id %q", e.name, e.id)
		}
		b = append(fmt.Appendf(b, "%s %s\x00", e.mode, e.name), id...)
	}
	return r.object("tree", b)
}

// commit writes a commit of the tree and points main at it.
func (r repo) commit(tree string) error {
	who := "escape <escape@localhost> 0 +0000"
	id, err := r.object("commit", fmt.Appendf(nil, "tree %s\nauthor %s\ncommitter %s\n\nescape\n", tree, who, who))
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(r.dir, ".git", "refs", "heads", "main"), []byte(id+"\n"), 0o644)
}

// index writes a version 2 index of the entries with no stat data, as
// `update-index --cacheinfo` leaves them. The mode is the tree mode.
func (r repo) index(entries ...entry) error {
	slices.SortFunc(entries, func(a, b entry) int { return strings.Compare(a.name, b.name) })
	b := []byte("DIRC")
	b = binary.BigEndian.AppendUint32(b, 2)
	b = binary.BigEndian.AppendUint32(b, uint32(len(entries)))
	for _, e := range entries {
		id, err := hex.DecodeString(e.id)
		if err != nil || len(id) != 20 {
			return fmt.Errorf("index entry %s: bad id %q", e.name, e.id)
		}
		var mode uint32
		if _, err := fmt.Sscanf(e.mode, "%o", &mode); err != nil {
			return fmt.Errorf("index entry %s: bad mode %q", e.name, e.mode)
		}
		start := len(b)
		for _, f := range []uint32{0, 0, 0, 0, 0, 0, mode, 0, 0, 0} { // ctime, mtime, dev, ino, mode, uid, gid, size
			b = binary.BigEndian.AppendUint32(b, f)
		}
		b = append(b, id...)
		b = binary.BigEndian.AppendUint16(b, uint16(min(len(e.name), 0xFFF)))
		b = append(b, e.name...)
		for b = append(b, 0); (len(b)-start)%8 != 0; {
			b = append(b, 0)
		}
	}
	sum := sha1.Sum(b)
	return os.WriteFile(filepath.Join(r.dir, ".git", "index"), append(b, sum[:]...), 0o644)
}
