// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/omkhar/workcell/v2/escape/sandbox"
	internalpins "github.com/omkhar/workcell/v2/internal/pins"
	providers "github.com/omkhar/workcell/v2/internal/provider"
	rows "github.com/omkhar/workcell/v2/pins"
)

// The pin smoke rows (B6), one per provider that installs a binary. The
// judge serves a fake Messages API under the provider's first host (SPEC T8)
// and has the host install a fixture agent from its own loopback: it prints
// its version, and the probe makes the session's call itself, the guest
// having no curl. The host must refuse bytes whose digest is not the row's,
// which a naive sandbox does not. Then, if the provider's row under pins/
// differs from the base branch's (GATE_BASE, else origin/main), the host
// installs that artifact from upstream by URL and digest (B8) and the real
// agent runs in the guest: --version, then the smoke command below with
// the placeholder in the provider's variable. Only the real key makes the
// fake answer. A provider with no command is smoked by --version and the
// probe's own call, as the fixture is.
var smokeCommands = map[string][]string{"claude": {"-p", "hi", "--output-format", "text"}}

const smokeVersion = "5.5.5"

// events: the Messages API's stream, as pairs of event name and data.
var events = []string{
	"message_start", `{"type":"message_start","message":{"id":"msg_fake","type":"message","role":"assistant","model":"fake","content":[],"stop_reason":null,"usage":{"input_tokens":1,"output_tokens":1}}}`,
	"content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`,
	"content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}`,
	"content_block_stop", `{"type":"content_block_stop","index":0}`,
	"message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":1}}`,
	"message_stop", `{"type":"message_stop"}`,
}

const message = `{"id":"msg_fake","type":"message","role":"assistant","model":"fake","content":[{"type":"text","text":"hello"}],"stop_reason":"end_turn","stop_sequence":null,"usage":{"input_tokens":1,"output_tokens":1}}`

// messages is the fake API: a POST to /v1/messages carrying want in header
// gets a 200, streamed when it asks; any other credential 401; any other path 404.
func messages(header, want string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Stream bool }
		switch {
		case r.Method != http.MethodPost || r.URL.Path != "/v1/messages":
			http.NotFound(w, r)
		case r.Header.Get(header) != want:
			http.Error(w, `{"type":"error","error":{"type":"authentication_error","message":"invalid credential"}}`, http.StatusUnauthorized)
		default:
			json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req)
			if !req.Stream {
				w.Header().Set("Content-Type", "application/json")
				io.WriteString(w, message)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			for i := 0; i < len(events); i += 2 {
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", events[i], events[i+1])
			}
		}
	}
}

// pinSmoke is the rows: a Want is fixed before the judge runs.
func pinSmoke() []Test {
	all, _ := providers.All()
	var out []Test
	for _, p := range all {
		if p.Install.Method == "binary" && len(p.Secrets) > 0 && len(p.Hosts) > 1 {
			out = append(out, Test{ID: "B6", Name: "pin-smoke-" + p.Name, Probe: smokeProbe, Host: smokeJudge(p), Bound: 15 * time.Minute, // a download may be 100 MB or more

				Want: Want{Workspace: true, Allow: p.Hosts, Header: p.Secrets[0].Header, Resolver: judgeResolver, Isolated: true, Secret: true}})
		}
	}
	return out
}

// changedPin is the guest row the provider installs, when it has an artifact
// for this architecture and its file differs byte for byte from the base's.
func changedPin(name string) (*internalpins.Pin, error) {
	all, err := rows.All()
	if err != nil {
		return nil, err
	}
	i := slices.IndexFunc(all, func(p internalpins.Pin) bool { return p.Name == name && p.Class == internalpins.Guest })
	if i < 0 || all[i].Artifacts[runtime.GOARCH].URL == "" {
		return nil, nil
	}
	base := cmp.Or(os.Getenv("GATE_BASE"), "refs/remotes/origin/main")
	out, err := exec.Command("git", "diff", "--name-only", base, "--", ":(top)pins/"+name+".json").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("compare pins/%s.json with %s: %v: %s", name, base, err, bytes.TrimSpace(out))
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return nil, nil
	}
	return &all[i], nil
}

// smokeJudge runs the fixture, the refusal and the changed pin, if any.
func smokeJudge(p providers.Provider) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		pin, err := changedPin(p.Install.Pin)
		if err != nil {
			return false, "", err
		}
		key := p.Secrets[0]
		api, other := &canary{name: s.Allow[0], respond: messages(s.Secret.Header, key.Prefix+s.Secret.Value)}, &canary{name: s.Allow[1], respond: http.NotFound}
		ns, stop, err := serveTwo(ctx, s, nil, api, other)
		if err != nil {
			return false, "", err
		}
		defer ns.stop()
		defer stop()
		cfg, err := certificate("127.0.0.1")
		if err != nil {
			return false, "", err
		}
		src, err := serve(cfg)
		if err != nil {
			return false, "", err
		}
		defer src.stop()
		var notes []string
		failed := false
		smoke := func(label, version string, cmd []string) error {
			from := len(api.requests())
			r, err := s.Run(append([]string{p.Binary, version, api.name, api.addr, s.Secret.Header, key.Prefix, s.Secret.Env, key.Env}, cmd...)...)
			saw := slices.ContainsFunc(api.requests()[from:], func(q request) bool { return q.headers.Get(s.Secret.Header) == key.Prefix+s.Secret.Value })
			if err == nil && (r.Status != "ok" || !saw) {
				failed = true
				label += " FAILED"
			}
			notes = append(notes, fmt.Sprintf("%s: %s, the fake API saw the real key: %t", label, says(r), saw))
			return err
		}
		if _, err := install(ctx, s, src, p.Name, smokeVersion, nil); err != nil {
			return false, "", err
		}
		if err := smoke("fixture", smokeVersion, nil); err != nil {
			return false, "", err
		}
		if _, refused := install(ctx, s, src, p.Name, "7.7.7", []byte("#!/bin/sh\necho 6.6.6\n")); refused == nil {
			failed, notes = true, append(notes, "the host installed "+p.Name+" from bytes whose digest is not the row's")
		}
		if pin != nil {
			label, art := p.Install.Pin+" "+pin.Version, pin.Artifacts[runtime.GOARCH]
			if _, err := s.Install(ctx, sandbox.Layer{Agent: p.Name, Version: pin.Version, URL: art.URL, Digest: art.SHA256}); err != nil {
				failed, notes = true, append(notes, label+" FAILED: the host could not install the pinned artifact: "+err.Error())
			} else if err := smoke(label, pin.Version, smokeCommands[p.Name]); err != nil {
				return false, "", err
			}
		}
		return !failed, strings.Join(notes, "; "), nil
	}
}

// smokeProbe runs the agent. args: its binary and version, the fake API's
// name and address, the header and prefix the credential goes in, the
// variable holding the placeholder and the one the agent reads it from, then
// its smoke command; with none the probe makes the call itself. "ok" means
// --version printed the version and exited 0, and the session exited 0.
func smokeProbe(args []string) Result {
	if len(args) < 8 {
		return Result{Status: "error", Detail: "want binary, version, name, address, header, prefix, two variables and a command"}
	}
	bin, version, name, addr, header, prefix, from, to, cmd := args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8:]
	placeholder := os.Getenv(from)
	vexit, vout := ran(30*time.Second, nil, bin, "--version")
	var sexit, sout string
	if len(cmd) > 0 {
		sexit, sout = ran(90*time.Second, []string{to + "=" + placeholder}, bin, cmd...)
		sout = sout[max(0, len(sout)-100):] // the tail
	} else { // the fixture's call
		req, _ := http.NewRequest(http.MethodPost, "https://"+name+":"+port(addr)+"/v1/messages", strings.NewReader(`{"model":"fake","max_tokens":1,"stream":true,"messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set(header, prefix+placeholder)
		resp, err := fetchWithin(req, map[string]string{name: addr}, &tls.Config{}, false, 20*time.Second)
		sexit, sout = "0", "http200"
		if err != nil {
			sexit, sout = "1", strings.ReplaceAll(short(err), " ", "_")
		} else if resp.StatusCode != http.StatusOK {
			sexit, sout = "1", "http"+strconv.Itoa(resp.StatusCode)
		}
	}
	status := "failed"
	if vexit == "0" && strings.Contains(vout, strings.TrimPrefix(version, "v")) && sexit == "0" { // a tag "v1.0.107" prints "1.0.107"
		status = "ok"
	}
	return Result{Status: status, Detail: fmt.Sprintf("version=%s exit=%s session=%s %s", vout[:min(len(vout), 40)], vexit, sexit, sout)}
}

// ran runs name for at most wait with env added: how it ended ("0" for
// success) and what it printed, one word.
func ran(wait time.Duration, env []string, name string, args ...string) (string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env, cmd.WaitDelay = append(os.Environ(), env...), 2*time.Second
	b, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	how := "0"
	switch {
	case ctx.Err() != nil:
		how = "timeout"
	case errors.As(err, &exit):
		how = strconv.Itoa(exit.ExitCode())
	case err != nil:
		how = strings.ReplaceAll(short(err), " ", "_")
	}
	return how, strings.Join(strings.Fields(string(b)), "_")
}
