// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
)

// A sign-in flow (I5): a [[secret]] row whose source is "signin:HOST/PATH"
// has no value of its own. Its token endpoint, PATH on HOST, an allowed name
// terminated like every other, issues the row's tokens in a JSON body:
// access_token, which the rule swaps in its header as it would a static
// secret, and refresh_token, which the guest presents back at the endpoint
// for new ones. The proxy reads each answer of the endpoint whole before
// the guest sees a byte, hands the tokens to the broker, which holds them
// in place of the ones before, and sends the guest the row's placeholder
// for the access token and a second one for the refresh token: the same two
// whatever the endpoint issues, so a client that keeps them across a
// refresh keeps something that still works. A real token the broker holds
// never appears in an answer, whatever its status, and a placeholder sent
// anywhere but its own place is refused as a static secret's would be.

// SignIn is the sign-in flow of a rule: the token endpoint and the refresh placeholder, as NewSignIn mints it.
type SignIn struct {
	Host, Path, Refresh string
}

// maxTokenBody bounds a request to or an answer from a token endpoint, which the proxy reads whole (I10, I12). A token body is a few hundred bytes.
const maxTokenBody = 256 << 10

// NewSignIn parses the source "signin:HOST/PATH" of a [[secret]] row: HOST a bare DNS name, with no port or scheme, which comes back canonical, and PATH an
// absolute one as NewTerminateRule takes it. The refresh placeholder is fresh.
func NewSignIn(source string) (*SignIn, error) {
	rest, ok := strings.CutPrefix(source, "signin:")
	host, p, found := strings.Cut(rest, "/")
	if !ok || !found {
		return nil, fmt.Errorf("sign-in source must be signin:HOST/PATH: %q", source)
	}
	s := &SignIn{Host: canonicalHost(host), Path: "/" + p, Refresh: NewPlaceholder()}
	if _, err := ParseAllowlist(s.Host+":443", "sign-in source"); err != nil {
		return nil, err
	}
	if !validPath(s.Path) {
		return nil, fmt.Errorf("sign-in path must hold printable ASCII without ? or #: %q", s.Path)
	}
	return s, nil
}

// validPath reports whether p begins with "/" and holds printable ASCII with no query or fragment, as a request target carries a path.
func validPath(p string) bool {
	return p != "" && p[0] == '/' && !strings.ContainsAny(p, "?#") && strings.IndexFunc(p, func(c rune) bool { return c < '!' || c > '~' }) < 0
}

// tokenEndpoint returns the rule whose token endpoint a request to u on host goes to: one whose path a common router would read as u's, taken as sent or as
// decoded and folded, in either case. The match is wide because an answer taken for another path would reach the guest unread (I5), while a request taken
// for the endpoint is only read whole and rewritten.
func (p *Proxy) tokenEndpoint(host string, u *url.URL) (TerminateRule, bool) {
	for _, r := range p.signin[host] {
		if strings.EqualFold(u.EscapedPath(), r.SignIn.Path) || strings.EqualFold(fold(u.Path), r.SignIn.Path) {
			return r, true
		}
	}
	return TerminateRule{}, false
}

// fold reads a decoded path as a router that takes a backslash for a slash, drops a ;param suffix from each segment and then resolves dot segments does.
func fold(p string) string {
	segs := strings.Split(strings.ReplaceAll(p, `\`, "/"), "/")
	for i, seg := range segs {
		segs[i], _, _ = strings.Cut(seg, ";")
	}
	return path.Clean(strings.Join(segs, "/"))
}

// tokenRequest reads the body of a request to rule's token endpoint and swaps the refresh placeholder in its refresh_token field for the refresh token the
// broker releases. It returns the body the request now carries, for the caller to wipe once it has gone, and a reason to refuse the request: a body over the
// bound, a broker that withholds the token, or a placeholder the body still carries anywhere else (I5). Accept-Encoding is dropped so that the answer comes
// back plain, or gzipped by a server that insists, which tokenResponse undoes.
func (p *Proxy) tokenRequest(r *http.Request, rule TerminateRule) ([]byte, string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxTokenBody+1))
	if err != nil || len(body) > maxTokenBody {
		return nil, "body_too_large"
	}
	mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	body, err = swapRefresh(mediaType, body, rule.SignIn.Refresh, func() ([]byte, error) {
		return p.broker.Refresh(r.Context(), rule.Host, rule.Header)
	})
	if err != nil {
		return nil, "broker_denied"
	}
	if placeholderAnywhere.Match(bytes.ToLower(body)) {
		return nil, "placeholder_unswapped"
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.Header.Del("Accept-Encoding")
	return body, ""
}

// swapRefresh swaps the refresh placeholder in the body of a request to the token endpoint for the refresh token that real releases: the value of the
// refresh_token field of a form, or of the top-level "refresh_token" string of a JSON object, as mediaType says. Anywhere else the placeholder stays, real is
// not asked, and the caller refuses the request.
func swapRefresh(mediaType string, body []byte, placeholder string, real func() ([]byte, error)) ([]byte, error) {
	switch mediaType {
	case "application/x-www-form-urlencoded":
		fields := bytes.Split(body, []byte("&"))
		for i, f := range fields {
			if k, v, _ := bytes.Cut(f, []byte("=")); string(k) != "refresh_token" || string(v) != placeholder {
				continue
			}
			value, err := real()
			if err != nil {
				return nil, err
			}
			fields[i] = []byte("refresh_token=" + url.QueryEscape(string(value)))
			clear(value)
			return bytes.Join(fields, []byte("&")), nil
		}
	case "application/json":
		var m map[string]json.RawMessage
		if json.Unmarshal(body, &m) != nil || string(m["refresh_token"]) != `"`+placeholder+`"` {
			break
		}
		value, err := real()
		if err != nil {
			return nil, err
		}
		m["refresh_token"], _ = json.Marshal(string(value))
		clear(value)
		return json.Marshal(m)
	}
	return body, nil
}

// tokenKey marks, in a request's context, the rule whose token endpoint it goes to, for tokenResponse.
type tokenKey struct{}

// tokenResponse rewrites the answer of a token endpoint before the guest reads a byte of it. The whole body is read, gunzipped when the server insisted on
// gzip, and on a 2xx JSON object the access_token and refresh_token strings go to the broker, which holds them from then on. Then every real token the broker
// holds for the row, old and new, is hidden behind its placeholder. An answer that cannot be read whole, decoded or recorded is refused: the guest gets a 502
// and none of its bytes.
func (p *Proxy) tokenResponse(resp *http.Response) error {
	rule, ok := resp.Request.Context().Value(tokenKey{}).(TerminateRule)
	if !ok {
		return nil
	}
	body, err := readToken(resp)
	if err == nil {
		body, err = p.learn(rule, resp.StatusCode, body)
	}
	if err != nil {
		p.Deny(rule.SignIn.Host, tlsPort, "token_answer_refused")
		return err
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.TransferEncoding = nil
	resp.Header.Del("Content-Encoding")
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return nil
}

// readToken reads the whole answer, at most maxTokenBody bytes, undoing gzip; another encoding cannot be read, so it is refused.
func readToken(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	var r io.Reader = io.LimitReader(resp.Body, maxTokenBody+1)
	switch enc := resp.Header.Get("Content-Encoding"); enc {
	case "":
	case "gzip", "x-gzip":
		z, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		r = io.LimitReader(z, maxTokenBody+1)
	default:
		return nil, fmt.Errorf("token answer has content encoding %q", enc)
	}
	body, err := io.ReadAll(r)
	if err == nil && len(body) > maxTokenBody {
		err = errors.New("token answer is over the bound")
	}
	return body, err
}

// learn hands the tokens a 2xx JSON object issues to the broker and returns
// body with every real token the broker holds for the row, before and after,
// hidden behind its placeholder. A 2xx that is not a JSON object is refused:
// a success answer is one (RFC 6749 section 5.1), and a body that only a
// lenient client reads, with a BOM or a trailing comma, could carry tokens
// the broker never sees (I5).
func (p *Proxy) learn(rule TerminateRule, status int, body []byte) ([]byte, error) {
	access, refresh := p.broker.Tokens(rule.Host, rule.Header)
	swaps := []swap{{access, rule.Placeholder}, {refresh, rule.SignIn.Refresh}}
	defer func() {
		for _, s := range swaps {
			clear(s.real)
		}
	}()
	if status/100 == 2 {
		var obj map[string]any // json.Valid first: Decode alone would take trailing bytes
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		if !json.Valid(body) || dec.Decode(&obj) != nil || obj == nil {
			return nil, errors.New("token answer is not a JSON object")
		}
		a, _ := obj["access_token"].(string)
		r, _ := obj["refresh_token"].(string)
		if a != "" || r != "" {
			if err := p.broker.Issue(rule.Host, rule.Header, []byte(a), []byte(r)); err != nil {
				return nil, err
			}
			swaps = append(swaps, swap{[]byte(a), rule.Placeholder}, swap{[]byte(r), rule.SignIn.Refresh})
		}
	}
	return hide(body, swaps), nil
}

// swap is one real value and the placeholder that stands for it; an empty value is none.
type swap struct {
	real        []byte
	placeholder string
}

// hide replaces every real value of swaps in body with its placeholder: in each string of every JSON value the body starts with, where an escape could spell a
// value differently to a client that reads the first value and stops, and then in the plain bytes of the whole.
func hide(body []byte, swaps []swap) []byte {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	var done int64
	for {
		var v any
		if dec.Decode(&v) != nil {
			break
		}
		_ = enc.Encode(hideIn(v, swaps))
		done = dec.InputOffset()
	}
	rest := append(bytes.TrimSuffix(out.Bytes(), []byte("\n")), body[done:]...)
	for _, s := range swaps {
		if len(s.real) > 0 {
			rest = bytes.ReplaceAll(rest, s.real, []byte(s.placeholder))
		}
	}
	return rest
}

// hideIn replaces every real value of swaps in each string of v, in place.
func hideIn(v any, swaps []swap) any {
	switch x := v.(type) {
	case string:
		for _, s := range swaps {
			if len(s.real) > 0 {
				x = strings.ReplaceAll(x, string(s.real), s.placeholder)
			}
		}
		return x
	case map[string]any:
		for k, e := range x {
			x[k] = hideIn(e, swaps)
		}
	case []any:
		for i, e := range x {
			x[i] = hideIn(e, swaps)
		}
	}
	return v
}
