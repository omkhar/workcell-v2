// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package pins is the rows under pins/, compiled in: one JSON file per upstream, each an
// internal/pins Pin, named for the file. The rows are data (A10): a provider's version
// lives in its row and nowhere else, and no Go file names one.
package pins

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	internalpins "github.com/omkhar/workcell/v2/internal/pins"
)

//go:embed *.json
var files embed.FS

// All is every row compiled into the binary, in file-name order.
var All = sync.OnceValues(func() ([]internalpins.Pin, error) { return Load(files) })

// Load reads every *.json of the root of fsys, in name order. A file is named for its
// row. Any fault refuses the whole set.
func Load(fsys fs.FS) ([]internalpins.Pin, error) {
	names, err := fs.Glob(fsys, "*.json")
	if err != nil {
		return nil, err
	}
	var out []internalpins.Pin
	for _, file := range names {
		b, err := fs.ReadFile(fsys, file)
		if err != nil {
			return nil, err
		}
		var p internalpins.Pin
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		if want := strings.TrimSuffix(file, ".json"); p.Name != want {
			return nil, fmt.Errorf("%s: row name %q is not the file's name %q", file, p.Name, want)
		}
		out = append(out, p)
	}
	return out, nil
}
