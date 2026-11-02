// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package rootfs

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrPath means a path was empty, named the root where a name was needed, or held a
	// component that is empty, ".", "..", longer than 255 bytes or holds a NUL byte.
	ErrPath = errors.New("rootfs: bad path")
	// ErrNotFound means a path, or the parent of a path, does not exist.
	ErrNotFound = errors.New("rootfs: no such path")
	// ErrNotDir means a path component that must be a directory is not one.
	ErrNotDir = errors.New("rootfs: not a directory")
	// ErrLinkDir means a hard link to a directory was requested.
	ErrLinkDir = errors.New("rootfs: cannot hard-link a directory")
	// ErrBadNode means a Node cannot be written to an image.
	ErrBadNode = errors.New("rootfs: bad node")
	// ErrTooLarge means the tree does not fit in an image this package can write.
	ErrTooLarge = errors.New("rootfs: tree too large")
)

// Kind is the type of a tree entry.
type Kind uint8

// The kinds of tree entry.
const (
	Dir Kind = iota + 1
	File
	Symlink
	CharDev
	BlockDev
	FIFO
)

const (
	maxName    = 255
	maxTarget  = blockSize - 1
	maxMajor   = 1<<12 - 1
	maxMinor   = 1<<20 - 1
	permAndSug = 0o7777
)

// Node is one inode. Which fields count depends on Kind: Data for File, Target for
// Symlink, Major and Minor for CharDev and BlockDev. Mode holds the permission bits
// plus setuid, setgid and sticky, and nothing else.
type Node struct {
	Kind         Kind
	Mode         uint32
	UID, GID     uint32
	Data         []byte
	Target       string
	Major, Minor uint32

	kids map[string]*Node
}

// Tree is an in-memory file tree. The zero value is not usable; call NewTree.
// A Tree is not safe for concurrent use.
type Tree struct {
	root *Node
}

// NewTree returns a tree holding only the root directory: mode 0755, owner 0:0.
func NewTree() *Tree {
	return &Tree{root: &Node{Kind: Dir, Mode: 0o755, kids: map[string]*Node{}}}
}

// Lookup returns the live node at p, or nil. "/" and "" name the root. The caller may
// change the node's Mode, UID and GID; every path that hard-links it sees the change.
func (t *Tree) Lookup(p string) *Node {
	parts, err := split(p)
	if err != nil {
		return nil
	}
	n, err := t.walk(parts)
	if err != nil {
		return nil
	}
	return n
}

// Put adds the entry n at p, or replaces whatever is there, of any kind. The parent
// must exist and be a directory; Put never creates parents. The tree keeps its own
// copy of n, so a Dir arrives empty, but it keeps the Data slice, which the caller
// must then not change. The root cannot be replaced; change Lookup("/") instead.
func (t *Tree) Put(p string, n Node) error {
	parts, err := split(p)
	if err != nil {
		return err
	}
	if len(parts) == 0 {
		return fmt.Errorf("%w: the root cannot be replaced", ErrPath)
	}
	if err := n.validate(); err != nil {
		return err
	}
	parent, err := t.dir(parts[:len(parts)-1])
	if err != nil {
		return err
	}
	n.kids = nil
	if n.Kind == Dir {
		n.kids = map[string]*Node{}
	}
	parent.kids[parts[len(parts)-1]] = &n
	return nil
}

// Link makes newp another name for the existing non-directory at oldp, replacing
// whatever is at newp. The two names then share one inode.
func (t *Tree) Link(oldp, newp string) error {
	src := t.Lookup(oldp)
	if src == nil {
		return fmt.Errorf("%w: %q", ErrNotFound, oldp)
	}
	if src.Kind == Dir {
		return ErrLinkDir
	}
	parts, err := split(newp)
	if err != nil {
		return err
	}
	if len(parts) == 0 {
		return fmt.Errorf("%w: the root cannot be replaced", ErrPath)
	}
	parent, err := t.dir(parts[:len(parts)-1])
	if err != nil {
		return err
	}
	parent.kids[parts[len(parts)-1]] = src
	return nil
}

// Remove deletes the entry at p, and everything below it if it is a directory. Other
// names of a hard-linked file stay.
func (t *Tree) Remove(p string) error {
	parts, err := split(p)
	if err != nil {
		return err
	}
	if len(parts) == 0 {
		return fmt.Errorf("%w: the root cannot be removed", ErrPath)
	}
	parent, err := t.dir(parts[:len(parts)-1])
	if err != nil {
		return err
	}
	name := parts[len(parts)-1]
	if _, ok := parent.kids[name]; !ok {
		return fmt.Errorf("%w: %q", ErrNotFound, p)
	}
	delete(parent.kids, name)
	return nil
}

// Clear removes every child of the directory at p and keeps the directory itself, as
// an opaque directory in an OCI layer needs.
func (t *Tree) Clear(p string) error {
	parts, err := split(p)
	if err != nil {
		return err
	}
	d, err := t.dir(parts)
	if err != nil {
		return err
	}
	clear(d.kids)
	return nil
}

// walk follows parts from the root and returns the node at the end, of any kind.
func (t *Tree) walk(parts []string) (*Node, error) {
	n := t.root
	for _, c := range parts {
		if n.Kind != Dir {
			return nil, fmt.Errorf("%w: %q", ErrNotDir, c)
		}
		next, ok := n.kids[c]
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrNotFound, c)
		}
		n = next
	}
	return n, nil
}

// dir is walk for a parent: the node at the end must be a directory.
func (t *Tree) dir(parts []string) (*Node, error) {
	n, err := t.walk(parts)
	if err == nil && n.Kind != Dir {
		err = fmt.Errorf("%w: %q", ErrNotDir, strings.Join(parts, "/"))
	}
	return n, err
}

// split cuts a slash-separated path into checked components. One leading slash is
// allowed; "" and "/" give no components.
func split(p string) ([]string, error) {
	p = strings.TrimPrefix(p, "/")
	if p == "" {
		return nil, nil
	}
	parts := strings.Split(p, "/")
	for _, c := range parts {
		if c == "" || c == "." || c == ".." || len(c) > maxName || strings.IndexByte(c, 0) >= 0 {
			return nil, fmt.Errorf("%w: %q", ErrPath, p)
		}
	}
	return parts, nil
}

func (n *Node) validate() error {
	switch {
	case n.Kind < Dir || n.Kind > FIFO:
		return fmt.Errorf("%w: unknown kind %d", ErrBadNode, n.Kind)
	case n.Mode&^permAndSug != 0:
		return fmt.Errorf("%w: mode %#o has bits beyond 07777", ErrBadNode, n.Mode)
	case n.Kind == Symlink && (n.Target == "" || len(n.Target) > maxTarget || strings.IndexByte(n.Target, 0) >= 0):
		return fmt.Errorf("%w: symlink target must be 1 to %d bytes without NUL", ErrBadNode, maxTarget)
	case (n.Kind == CharDev || n.Kind == BlockDev) && (n.Major > maxMajor || n.Minor > maxMinor):
		return fmt.Errorf("%w: device %d:%d out of range", ErrBadNode, n.Major, n.Minor)
	}
	return nil
}
