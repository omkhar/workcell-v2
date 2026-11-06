// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package advisory asks a public advisory database whether a published advisory
// affects a pinned version and a newer release fixes it (B4). It sits outside
// the bump-tool line count, like internal/artifact.
package advisory

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"time"

	"github.com/omkhar/workcell/v2/internal/pins"
)

const (
	// OSV is the query endpoint of the OSV database, the one production uses.
	OSV      = "https://api.osv.dev/v1/query"
	maxBody  = 4 << 20
	maxPages = 8
	timeout  = 30 * time.Second
)

type answer struct {
	Vulns []vuln `json:"vulns"`
	Next  string `json:"next_page_token"`
}

type vuln struct {
	ID        string `json:"id"`
	Withdrawn string `json:"withdrawn"`
	Affected  []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Versions []string `json:"versions"`
		Ranges   []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced   string `json:"introduced"`
				Fixed        string `json:"fixed"`
				LastAffected string `json:"last_affected"`
				Limit        string `json:"limit"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// Lookup asks the database at db (production passes OSV) about p. It has three
// outcomes. (nil, nil): the database answered and no published advisory affects
// p.Version with a fix, or p has no Package or no stable version to ask about.
// (adv, nil): a published advisory affects p.Version and names a fix; adv is the
// one with the highest fix. (nil, err): the database could not be consulted or
// its answer could not be read; the caller passes nil to pins.Select, so the
// normal cool-off stays in force, and reports err (W8). A failure is never
// (nil, nil). The error names the pin and echoes nothing the server sent.
func Lookup(ctx context.Context, client *http.Client, db string, p pins.Pin) (*pins.Advisory, error) {
	cur, ok := pins.ParseVersion(p.Version)
	if p.Package == (pins.Package{}) || !ok {
		return nil, nil
	}
	fail := func(why string) (*pins.Advisory, error) {
		return nil, fmt.Errorf("advisory lookup for pin %q: %s", p.Name, why)
	}
	if u, err := url.Parse(db); err != nil || u.Scheme != "https" {
		return fail("the database address is not https")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	var best *pins.Advisory
	var bestFix pins.Version
	token := ""
	for range maxPages {
		q := map[string]any{"package": map[string]string{"ecosystem": p.Package.Ecosystem, "name": p.Package.Name}, "version": p.Version}
		if token != "" {
			q["page_token"] = token
		}
		body, _ := json.Marshal(q)
		data, why := post(ctx, &c, db, body)
		if why != "" {
			return fail(why)
		}
		var a answer
		if json.Unmarshal(data, &a) != nil {
			return fail("malformed answer")
		}
		for _, v := range a.Vulns {
			if adv, fix, ok := v.match(p, cur); ok && (best == nil || pins.Compare(fix, bestFix) > 0) {
				best, bestFix = &adv, fix
			}
		}
		if token = a.Next; token == "" {
			return best, nil
		}
	}
	return fail("more than " + strconv.Itoa(maxPages) + " pages")
}

// post sends body and returns the answer, or a fixed phrase for why it cannot.
func post(ctx context.Context, c *http.Client, db string, body []byte) ([]byte, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, db, bytes.NewReader(body))
	if err != nil {
		return nil, "bad request"
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return nil, "request failed"
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "status " + strconv.Itoa(resp.StatusCode)
	}
	if resp.ContentLength > maxBody {
		return nil, "answer too large"
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if len(data) > maxBody {
		return nil, "answer too large"
	}
	if err != nil {
		return nil, "answer cut short"
	}
	return data, ""
}

// match reports the advisory v makes about p at cur, and its fix. A withdrawn
// vuln, one whose id is not a short plain token (the id reaches a public issue
// and pull request), a package other than p's and a span without a stable fix
// match nothing. Within an affected entry the fix is the highest stable fix of
// all its ranges, so a version at or above it lies outside every closed range,
// and an entry with a range left open matches nothing.
func (v vuln) match(p pins.Pin, cur pins.Version) (adv pins.Advisory, fix pins.Version, ok bool) {
	if v.Withdrawn != "" || !plainID(v.ID) {
		return
	}
	var listed pins.Advisory // the highest fix above cur, for a version the entry lists
	var listedFix pins.Version
	for _, a := range v.Affected {
		if a.Package.Ecosystem != p.Package.Ecosystem || a.Package.Name != p.Package.Name {
			continue
		}
		isListed := slices.Contains(a.Versions, p.Version)
		var top pins.Version // the highest stable fix of the entry
		topText, hitFrom, hit, unclosed := "", "", false, false
		for _, r := range a.Ranges {
			if r.Type != "SEMVER" && r.Type != "ECOSYSTEM" {
				continue
			}
			from, open := "", false
			for _, e := range r.Events {
				switch {
				case e.Introduced != "":
					from, open = e.Introduced, true
					if from == "0" { // every version
						from = ""
					}
				case e.Fixed != "" && open:
					open = false
					f, fok := pins.ParseVersion(e.Fixed)
					if !fok {
						continue
					}
					if topText == "" || pins.Compare(f, top) > 0 {
						top, topText = f, e.Fixed
					}
					lo, lok := pins.Version{}, true
					if from != "" {
						lo, lok = pins.ParseVersion(from)
					}
					if pins.Compare(cur, f) < 0 && lok && pins.Compare(lo, cur) <= 0 && (!hit || pins.Compare(f, top) >= 0) {
						hit, hitFrom = true, from
					}
				case e.LastAffected != "":
					open = false
				}
				if e.Limit != "" {
					break
				}
			}
			unclosed = unclosed || open
		}
		if unclosed || topText == "" || pins.Compare(cur, top) >= 0 {
			continue
		}
		switch {
		case hit && (!ok || pins.Compare(top, fix) > 0):
			adv, fix, ok = pins.Advisory{ID: v.ID, Introduced: hitFrom, Fixed: topText}, top, true
		case !hit && isListed && (listed.ID == "" || pins.Compare(top, listedFix) > 0):
			listed, listedFix = pins.Advisory{ID: v.ID, Fixed: topText}, top
		}
	}
	if !ok && listed.ID != "" {
		return listed, listedFix, true
	}
	return
}

// plainID reports whether id is 1 to 64 bytes of letters, digits, "." and "-".
func plainID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if c != '.' && c != '-' && (c < '0' || c > '9') && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
			return false
		}
	}
	return true
}
