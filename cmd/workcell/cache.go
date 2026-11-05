// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package main

import (
	"flag"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/omkhar/workcell/v2/internal/vmm"
)

// A cache is one ext4 image, <data>/caches/<name>.ext4, that a session gets as /cache/<name>:
// read-only unless the flag says NAME:rw. The host never mounts or reads it; it only attaches
// it to a guest, with the drive's read-only flag as the enforcement (I1, A1).

var cacheName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// cacheFlag adds the repeatable --cache to fs, its values unjudged (see parseCaches).
func cacheFlag(fs *flag.FlagSet, into *[]string) {
	fs.Func("cache", "attach the dependency cache NAME at /cache/NAME, read-only; NAME:rw persists what the session writes; repeatable", func(s string) error {
		*into = append(*into, s)
		return nil
	})
}

// parseCaches judges the values of --cache: NAME or NAME:rw, each name once, in order.
func parseCaches(values []string) ([]vmm.Cache, error) {
	var cs []vmm.Cache
	for _, v := range values {
		name, mode, rw := strings.Cut(v, ":")
		switch {
		case !cacheName.MatchString(name):
			return nil, fmt.Errorf("--cache %q: a name is 1 to 32 of a-z, 0-9, _ and -, and does not start with _ or -", v)
		case rw && mode != "rw":
			return nil, fmt.Errorf("--cache %q: the only mode is :rw", v)
		case slices.ContainsFunc(cs, func(c vmm.Cache) bool { return c.Name == name }):
			return nil, fmt.Errorf("--cache %s is given twice", name)
		}
		cs = append(cs, vmm.Cache{Name: name, Writable: rw})
	}
	return cs, nil
}

// cachePath is the image of the cache name under the data directory dir.
func cachePath(dir, name string) string { return filepath.Join(dir, "caches", name+".ext4") }

// cacheLine is explain's line for c, whose image is at image and is there or not.
func cacheLine(c vmm.Cache, image string, exists bool) string {
	switch {
	case c.Writable && exists:
		return fmt.Sprintf("cache %s: /cache/%[1]s, writable (persists in %s for later sessions)", c.Name, image)
	case c.Writable:
		return fmt.Sprintf("cache %s: /cache/%[1]s, writable (persists in %s for later sessions; it does not exist yet, the first session creates it)", c.Name, image)
	case exists:
		return fmt.Sprintf("cache %s: /cache/%[1]s, read-only (the session may write there; nothing it writes is kept)", c.Name)
	}
	return fmt.Sprintf("cache %s: does not exist yet; workcell run refuses it until --cache %[1]s:rw creates it", c.Name)
}
