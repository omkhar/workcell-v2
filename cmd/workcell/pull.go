// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/omkhar/workcell/v2/internal/guest"
)

// bounds is how much of a work tree the host takes: entries, bytes of names and bytes of
// data. The data can be no more than the session's image holds, so that is its bound.
type bounds struct {
	entries int
	names   int
	bytes   int64
}

// manifest is what the guest says its work tree holds, judged entry by entry before any of
// it is written or compared (I8). The guest chose every path, so each is refused unless it
// is a plain relative path of sound components, and two paths that are the same under case
// folding are refused together: a launch host folds case (P6), and there the second would
// land on the first. Nothing the guest says beyond this is trusted; the bytes come later.
type manifest struct {
	limit   bounds
	entries []guest.Entry
	folded  map[string]bool
	names   int
	bytes   int64
}

// add judges one entry and keeps it.
func (m *manifest) add(e guest.Entry) error {
	if len(m.entries) >= m.limit.entries {
		return fmt.Errorf("more than %d entries", m.limit.entries)
	}
	if err := checkPath(e.Path); err != nil {
		return fmt.Errorf("path %s: %w", shown(e.Path), err)
	}
	if e.Kind == guest.KindLink && (e.Target == "" || strings.IndexByte(e.Target, 0) >= 0) {
		return fmt.Errorf("link %s: the target is empty or holds NUL", shown(e.Path))
	}
	if m.names += len(e.Path) + len(e.Target); m.names > m.limit.names {
		return fmt.Errorf("more than %d bytes of names", m.limit.names)
	}
	if m.bytes += e.Size; m.bytes > m.limit.bytes {
		return fmt.Errorf("more than %d bytes of files, which the session's image cannot hold", m.limit.bytes)
	}
	key := fold(e.Path)
	if m.folded[key] {
		return fmt.Errorf("path %s: another path is the same under case folding", shown(e.Path))
	}
	if m.folded == nil {
		m.folded = map[string]bool{}
	}
	m.folded[key] = true
	m.entries = append(m.entries, e)
	return nil
}

// checkPath refuses a path that could name anything but one entry beneath the directory
// the tree goes into: absolute, empty, holding NUL, not UTF-8, or with a component that
// is empty, ".", ".." or ".git" in any case.
func checkPath(p string) error {
	switch {
	case p == "":
		return errors.New("empty")
	case len(p) > guest.MaxPath:
		return fmt.Errorf("longer than %d bytes", guest.MaxPath)
	case strings.IndexByte(p, 0) >= 0:
		return errors.New("holds NUL")
	case !utf8.ValidString(p):
		return errors.New("not UTF-8")
	case p[0] == '/':
		return errors.New("absolute")
	}
	for _, c := range strings.Split(p, "/") {
		switch {
		case c == "":
			return errors.New("an empty component")
		case c == "." || c == "..":
			return fmt.Errorf("a %q component", c)
		case strings.EqualFold(c, ".git"):
			return errors.New("a .git component")
		}
	}
	return nil
}

// fold maps s so that two strings are equal under strings.EqualFold exactly when their
// folds are equal: each rune goes to the smallest in its simple-fold orbit.
func fold(s string) string {
	return strings.Map(func(r rune) rune {
		least := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			least = min(least, f)
		}
		return least
	}, s)
}

// shown is a path the guest chose, as one line of output may carry it: quoted when it
// holds anything a terminal could misread.
func shown(p string) string {
	if q := strconv.Quote(p); q != `"`+p+`"` {
		return q
	}
	return p
}
