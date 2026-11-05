// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package pins

import (
	"slices"
	"testing"
	"testing/fstest"

	internalpins "github.com/omkhar/workcell/v2/internal/pins"
)

// TestLoad: a row is named for its file and decodes to a Pin; a misnamed row, a row that
// is not JSON, and a row that is not an object each refuse the whole set.
func TestLoad(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  []string // the row names, in order
		fails bool
	}{
		{"none", nil, nil, false},
		{"two in name order", map[string]string{"b.json": `{"Name":"b","Version":"2"}`, "a.json": `{"Name":"a"}`}, []string{"a", "b"}, false},
		{"other files ignored", map[string]string{"a.json": `{"Name":"a"}`, "notes.txt": "x"}, []string{"a"}, false},
		{"unpinned row", map[string]string{"a.json": `{"Name":"a","Version":"","Artifacts":null,"Timestamps":null,"Released":"0001-01-01T00:00:00Z","Previous":null}`}, []string{"a"}, false},
		{"misnamed", map[string]string{"a.json": `{"Name":"b"}`}, nil, true},
		{"not json", map[string]string{"a.json": `{`}, nil, true},
		{"not an object", map[string]string{"a.json": `[1]`}, nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for name, body := range tc.files {
				fsys[name] = &fstest.MapFile{Data: []byte(body)}
			}
			rows, err := Load(fsys)
			if (err != nil) != tc.fails {
				t.Fatalf("Load: err %v, want failure %v", err, tc.fails)
			}
			var got []string
			for _, r := range rows {
				got = append(got, r.Name)
			}
			if len(got) != len(tc.want) || (len(got) > 0 && got[0] != tc.want[0]) || (len(got) > 1 && got[1] != tc.want[1]) {
				t.Errorf("rows %v, want %v", got, tc.want)
			}
		})
	}
	if all, err := All(); err != nil || !slices.ContainsFunc(all, func(p internalpins.Pin) bool { return p.Name == "debian" }) {
		t.Errorf("the compiled-in rows lack debian: %v", err)
	}
}
