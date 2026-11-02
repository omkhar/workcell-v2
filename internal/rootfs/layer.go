// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package rootfs

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"slices"
	"strings"
)

const (
	whiteoutPrefix = ".wh."
	opaqueMarker   = ".wh..wh..opq"
	maxPath        = 4096 // Linux PATH_MAX; also keeps mkParents quick on a hostile pax path
)

// applyLayer reads an uncompressed tar from r and applies it to t on top of what is
// there, as the OCI image spec says. It never follows a symlink and never touches
// the disk: every member becomes a Node. limit bounds both the tar stream and the
// file data; the bigger of the two is returned.
//
// A member name must be relative and free of "..", and a hard link must name an
// entry already in t; anything else is an error, and the member is not written.
// Missing parent directories are made as 0755 root-owned directories. A Dir member
// over an existing Dir only sets its owner and mode, so the layer below stays.
//
// A whiteout (".wh.<name>") removes <name> and an opaque marker (".wh..wh..opq")
// empties its directory. They apply in the order met, to everything already in t,
// including entries this same layer made earlier; real builders put them first.
func applyLayer(t *Tree, r io.Reader, limit int64) (int64, error) {
	in := &limited{r: r, n: limit}
	tr := tar.NewReader(in)
	dataLeft := limit
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return 0, tarErr(err)
		}
		if h.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		if err := applyMember(t, tr, h, &dataLeft); err != nil {
			return 0, fmt.Errorf("layer: member %q: %w", h.Name, err)
		}
	}
	return max(limit-in.n, limit-dataLeft), nil
}

func tarErr(err error) error {
	if errors.Is(err, errCap) {
		return errCap
	}
	return errors.New("layer: tar unreadable")
}

func applyMember(t *Tree, tr *tar.Reader, h *tar.Header, dataLeft *int64) error {
	name, err := memberPath(h.Name)
	if err != nil {
		return err
	}
	dir, base := path.Split(name)
	dir = strings.TrimSuffix(dir, "/")
	if base == "" { // the root itself: "./" or "."
		return nil
	}
	if strings.HasPrefix(base, whiteoutPrefix) {
		return whiteout(t, dir, base)
	}
	if h.Uid < 0 || h.Gid < 0 || h.Uid > math.MaxUint32 || h.Gid > math.MaxUint32 {
		return errors.New("owner out of range")
	}
	n := Node{Mode: uint32(h.Mode & permAndSug), UID: uint32(h.Uid), GID: uint32(h.Gid)}
	switch h.Typeflag {
	case tar.TypeDir:
		n.Kind = Dir
	case tar.TypeReg:
		n.Kind = File
		if h.Size > *dataLeft {
			return errors.New("over the size cap")
		}
		data := make([]byte, h.Size)
		if _, err := io.ReadFull(tr, data); err != nil {
			return tarErr(err)
		}
		*dataLeft -= h.Size
		n.Data = data
	case tar.TypeSymlink:
		n.Kind, n.Target = Symlink, h.Linkname
	case tar.TypeChar, tar.TypeBlock:
		n.Kind = CharDev
		if h.Typeflag == tar.TypeBlock {
			n.Kind = BlockDev
		}
		if uint64(h.Devmajor) > maxMajor || uint64(h.Devminor) > maxMinor {
			return errors.New("device number out of range")
		}
		n.Major, n.Minor = uint32(h.Devmajor), uint32(h.Devminor)
	case tar.TypeFifo:
		n.Kind = FIFO
	case tar.TypeLink:
		old, err := memberPath(h.Linkname)
		if err != nil {
			return err
		}
		if err := mkParents(t, dir); err != nil {
			return err
		}
		return t.Link(old, name) // a target outside the tree is not in it: ErrNotFound
	default:
		return fmt.Errorf("unsupported tar type %q", h.Typeflag)
	}
	if err := mkParents(t, dir); err != nil {
		return err
	}
	if old := t.Lookup(name); n.Kind == Dir && old != nil && old.Kind == Dir {
		old.Mode, old.UID, old.GID = n.Mode, n.UID, n.GID
		return nil
	}
	return t.Put(name, n)
}

// whiteout applies the whiteout member base in directory dir. A target that is
// absent is not an error. A whiteout never creates anything.
func whiteout(t *Tree, dir, base string) error {
	var err error
	if base == opaqueMarker {
		err = t.Clear("/" + dir)
	} else {
		err = t.Remove(dir + "/" + strings.TrimPrefix(base, whiteoutPrefix))
	}
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}

// memberPath cleans a tar member name or hard-link target into a path relative to
// the root of the tree. An absolute name and a ".." component are refused here;
// the tree refuses the other malformed components.
func memberPath(name string) (string, error) {
	if strings.HasPrefix(name, "/") {
		return "", errors.New("absolute name")
	}
	if name == "" {
		return "", errors.New("empty name")
	}
	if len(name) > maxPath {
		return "", errors.New("name too long")
	}
	for strings.HasPrefix(name, "./") {
		name = name[2:]
	}
	name = strings.TrimSuffix(name, "/")
	if slices.Contains(strings.Split(name, "/"), "..") {
		return "", errors.New("name holds ..")
	}
	if name == "." {
		name = ""
	}
	_, err := split(name) // so that no parent is made for a name the tree will refuse
	return name, err
}

// mkParents makes every missing directory on dir, which is relative and may be empty.
func mkParents(t *Tree, dir string) error {
	for i := 0; i <= len(dir); i++ {
		if i < len(dir) && dir[i] != '/' {
			continue
		}
		if p := dir[:i]; p != "" && t.Lookup(p) == nil {
			if err := t.Put(p, Node{Kind: Dir, Mode: 0o755}); err != nil {
				return err
			}
		}
	}
	return nil
}
