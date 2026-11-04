// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package bump

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/omkhar/workcell/v2/internal/pins"
)

const (
	maxBody  = 8 << 20
	maxPages = 10
)

var (
	nextRE = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)
	shaRE  = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// GitHub drives the REST API of one repository. The commits it makes are made
// by the API, which signs them; it never runs git or gh (A8).
type GitHub struct {
	Client *http.Client
	API    string // the API root, such as https://api.github.com
	Repo   string // owner/name
	Token  string
}

type pull struct {
	Number       int
	Body         string
	ChangedFiles int `json:"changed_files"`
	Labels       []struct{ Name string }
	Base         struct{ Ref string }
	Head         struct {
		Ref, SHA string
		Repo     *struct {
			FullName string `json:"full_name"`
			Fork     bool
		}
	}
}

type file struct{ Filename, Status, Patch string }

type checkRun struct {
	Name, Status, Conclusion string
	HeadSHA                  string `json:"head_sha"`
}

// do sends one request to an absolute API URL and decodes a 2xx answer into
// out. Any other answer, or one that is not JSON, is Stopped(step).
func (g GitHub) do(ctx context.Context, step, method, url string, in, out any) (http.Header, error) {
	var rd io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return nil, Stopped(step)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}
	resp, err := g.Client.Do(req)
	if err != nil {
		return nil, Stopped(step)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil || resp.StatusCode/100 != 2 || (out != nil && json.Unmarshal(b, out) != nil) {
		return nil, Stopped(step)
	}
	return resp.Header, nil
}

func (g GitHub) url(format string, a ...any) string {
	return strings.TrimSuffix(g.API, "/") + "/repos/" + g.Repo + fmt.Sprintf(format, a...)
}

// list GETs every page of a listing, following rel="next" within the API root only.
func list[T any](ctx context.Context, g GitHub, step, url string) ([]T, error) {
	var all []T
	for range maxPages {
		var page []T
		h, err := g.do(ctx, step, http.MethodGet, url, nil, &page)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		m := nextRE.FindStringSubmatch(h.Get("Link"))
		if m == nil {
			return all, nil
		}
		if url = m[1]; !strings.HasPrefix(url, strings.TrimSuffix(g.API, "/")+"/") {
			return nil, Stopped(step)
		}
	}
	return nil, Stopped(step)
}

// class names the class of a bump pull request this repository opened against
// main; a fork's, or one against another base, is none.
func (g GitHub) class(pr pull) (pins.Class, bool) {
	r := pr.Head.Repo
	if pr.Base.Ref != "main" || r == nil || r.Fork || r.FullName != g.Repo {
		return "", false
	}
	for _, c := range classes {
		if strings.HasPrefix(pr.Head.Ref, "bump/"+string(c)+"-") {
			return c, true
		}
	}
	return "", false
}

// FilesOK reports whether every changed file is an added or modified regular
// row pins/<name>.json, and the listing holds all the pull request's files.
func FilesOK(fs []file, changed int) bool {
	if len(fs) != changed || changed == 0 {
		return false
	}
	for _, f := range fs {
		lines := strings.Split(f.Patch, "\n")
		switch {
		case !PathOK(f.Filename) || (f.Status != "added" && f.Status != "modified") || f.Patch == "":
			return false
		case f.Status == "added" && (len(lines) < 2 || lines[1] != "+{"):
			return false // a symbolic link's patch is its target, never a JSON object
		}
	}
	return true
}

// Green reports whether every check run on sha completed with success and one
// of them is named exactly gate.
func Green(runs []checkRun, total int, sha string) bool {
	gate := false
	for _, r := range runs {
		if r.HeadSHA != sha || r.Status != "completed" || r.Conclusion != "success" {
			return false
		}
		gate = gate || r.Name == "gate"
	}
	return gate && total == len(runs)
}

// merge squashes pull request n once, with the head the checks were read for,
// when its files are rows only and the gate is green.
func (t Tool) merge(ctx context.Context, n int) error {
	g := t.GitHub
	var pr pull
	if _, err := g.do(ctx, "read pull request", http.MethodGet, g.url("/pulls/%d", n), nil, &pr); err != nil {
		return err
	}
	class, ok := g.class(pr)
	if !ok {
		return Refused("pull request")
	}
	if !shaRE.MatchString(pr.Head.SHA) {
		return Refused("head")
	}
	fs, err := list[file](ctx, g, "list changed files", g.url("/pulls/%d/files?per_page=100", n))
	if err != nil {
		return err
	}
	if !FilesOK(fs, pr.ChangedFiles) {
		return Refused("changed path")
	}
	var cr struct { // one page: a head with more runs than a page holds waits
		Total int        `json:"total_count"`
		Runs  []checkRun `json:"check_runs"`
	}
	_, err = g.do(ctx, "list check runs", http.MethodGet, g.url("/commits/%s/check-runs?per_page=100", pr.Head.SHA), nil, &cr)
	switch {
	case err != nil:
		return err
	case class == pins.Trusted && (strings.Contains(pr.Body, securityNote) || slices.ContainsFunc(pr.Labels, func(l struct{ Name string }) bool { return l.Name == "security" })):
		fmt.Fprintln(t.Out, "waits for the maintainer:", n)
	case !Green(cr.Runs, cr.Total, pr.Head.SHA):
		fmt.Fprintln(t.Out, "waits for gate:", n)
	case t.DryRun:
		fmt.Fprintln(t.Out, "would merge:", n)
	default:
		in := map[string]string{"sha": pr.Head.SHA, "merge_method": "squash"}
		if _, err := g.do(ctx, "merge", http.MethodPut, g.url("/pulls/%d/merge", n), in, nil); err != nil {
			return err
		}
		fmt.Fprintln(t.Out, "merged:", n)
	}
	return nil
}

// propose opens the class's one pull request: a branch named by the class and
// the date, one API commit per row, and the security label where B4 says so.
func (t Tool) propose(ctx context.Context, class pins.Class, cs []Change) error {
	g := t.GitHub
	branch := "bump/" + string(class) + "-" + t.Now.UTC().Format("20060102")
	var ref struct{ Object struct{ SHA string } }
	if _, err := g.do(ctx, "read main", http.MethodGet, g.url("/git/ref/heads/main"), nil, &ref); err != nil {
		return err
	}
	in := map[string]string{"ref": "refs/heads/" + branch, "sha": ref.Object.SHA}
	if _, err := g.do(ctx, "create branch", http.MethodPost, g.url("/git/refs"), in, nil); err != nil {
		return err
	}
	security := false
	for _, c := range cs {
		security = security || c.Security
		old, err := os.ReadFile(filepath.Join(t.Pins, c.Old.Name+".json"))
		if err != nil {
			return Stopped("read pins")
		}
		sum := sha1.Sum(append([]byte(fmt.Sprintf("blob %d\x00", len(old))), old...)) // git's blob id of the row on main
		put := map[string]string{
			"message": fmt.Sprintf("bump: %s %s to %s", c.Old.Name, cmp.Or(c.Old.Version, "-"), c.New.Version),
			"content": base64.StdEncoding.EncodeToString(Row(c.New)),
			"branch":  branch,
			"sha":     hex.EncodeToString(sum[:]),
		}
		if _, err := g.do(ctx, "write row", http.MethodPut, g.url("/contents/pins/%s.json", c.Old.Name), put, nil); err != nil {
			return err
		}
	}
	var pr struct{ Number int }
	in = map[string]string{"title": "bump: " + string(class) + " pins", "head": branch, "base": "main", "body": body(cs, t.Now)}
	if _, err := g.do(ctx, "open pull request", http.MethodPost, g.url("/pulls"), in, &pr); err != nil {
		return err
	}
	if security {
		lb := map[string][]string{"labels": {"security"}}
		if _, err := g.do(ctx, "label", http.MethodPost, g.url("/issues/%d/labels", pr.Number), lb, nil); err != nil {
			return err
		}
	}
	fmt.Fprintln(t.Out, "opened pull request:", class, pr.Number)
	return nil
}

// issue opens the one issue of a verification failure (B5), unless an open
// issue already carries its exact title.
func (t Tool) issue(ctx context.Context, name string) error {
	if t.DryRun {
		fmt.Fprintln(t.Out, "would open issue:", name)
		return nil
	}
	g := t.GitHub
	title := "bump: verification failed: " + name
	is, err := list[struct{ Title string }](ctx, g, "list issues", g.url("/issues?state=open&per_page=100"))
	if err != nil {
		return err
	}
	for _, i := range is {
		if i.Title == title {
			return nil
		}
	}
	in := map[string]string{"title": title, "body": "The newest eligible release of pin " + name +
		" failed verification, so it is not pinned. The bump of this pin waits until a release verifies."}
	if _, err := g.do(ctx, "open issue", http.MethodPost, g.url("/issues"), in, nil); err != nil {
		return err
	}
	fmt.Fprintln(t.Out, "opened issue:", name)
	return nil
}
