// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/omkhar/workcell/v2/escape/sandbox"
)

// The I11 rows. The product has no helper process of its own (SPEC A9): the
// proxy and the resolver are parts of the one supervisor that owns the
// session's VM. So "the proxy dies" is that process dying as a crash kills
// it, SIGKILL, while the guest holds a connection the proxy served it. The
// adapter names the process (sandbox.Observe.Helper); the judge kills it and
// holds the host to the invariant: every process of the session goes with
// it, the held connection closes, no canary and no resolver hears from the
// guest again, and the run ends. What the guest says afterwards can count
// against the product, never for it.

// servable is the sandbox the rows want: an allowed name, bare, so that the
// host terminates the guest's connections to it and carries each request
// on to the canary itself, a denied name, the judge as the host's resolver,
// answering both names with the test host's address, and, so that the
// product's vetting accepts that address, the host side in a network of its
// own (SPEC T8). Both canaries share the listener at port 443 there.
var servable = Want{Allow: []string{"allowed.escape.test"}, Deny: []string{"denied.escape.test"}, Resolver: judgeResolver, Isolated: true}

// bind opens network/addr on the host side of s, where the product reaches
// the test host (sandbox.Observe.Bind), and as root on the test host when a
// port in the host's own network needs that.
func bind(ctx context.Context, s Session, network, addr string) (net.Listener, net.PacketConn, error) {
	ln, pc, err := s.Bind(ctx, network, addr)
	if errors.Is(err, syscall.EACCES) {
		return privileged(network, addr, s.Payload)
	}
	return ln, pc, err
}

// privileged binds network/addr in the host's own network as root (sandbox.RootBind).
func privileged(network, addr, payload string) (net.Listener, net.PacketConn, error) {
	return sandbox.RootBind(network, addr, payload, 0)
}

const (
	holdFor     = 5 * time.Second         // how long the guest holds its connection open, for the kill to land
	attemptWait = 1500 * time.Millisecond // what one attempt after the hold may take
	bootWait    = 8 * time.Second         // how long the guest has to boot and hold a connection
	deathWait   = 2 * time.Second         // how long SIGKILL has to take effect
	wakeWait    = 6 * time.Second         // how long the session has to go away after the death, the run included
	closeWithin = 2 * time.Second         // how soon after the death the held connection must close
	settle      = 300 * time.Millisecond  // a moment for a late request to show at a canary
)

// holdProbe is the guest of the I11 rows. It asks its resolver for the
// allowed name, fetches https://<allowed>/reach, once more after a pause
// when that fails, holds a second connection open on /stream until the far
// end closes it or holdFor passes, and then, as a program does after losing
// a connection, tries again: its resolver for both names and /after at both.
// args: allowed name, its address, denied name, its address.
func holdProbe(args []string) Result {
	if len(args) != 4 {
		return Result{Status: "error", Detail: "want allowed name, address, denied name, address"}
	}
	allowed, denied := args[0], args[2]
	addrs := map[string]string{allowed: args[1], denied: args[3]}
	t := targets{addrs: addrs}
	before := lookupName(allowed)
	r := report(fetch(t.get(allowed, "/reach"), addrs, &tls.Config{}, false))
	if r.Status != "served" {
		time.Sleep(300 * time.Millisecond)
		r = report(fetch(t.get(allowed, "/retry"), addrs, &tls.Config{}, false))
	}
	held := "skipped"
	if r.Status == "served" {
		held = holdOpen(t.get(allowed, "/stream"), addrs)
	}
	out := []string{"before-dns=" + before, "reach=" + r.Status, "held=" + held, "after-dns=" + lookupName(allowed), "after-dns-denied=" + lookupName(denied)}
	status := "unreached"
	for _, name := range []string{allowed, denied} {
		a := report(fetchWithin(t.get(name, "/after"), addrs, &tls.Config{}, false, attemptWait))
		if a.Status == "served" {
			status = "served"
		}
		out = append(out, "after-"+strings.TrimSuffix(name, ".escape.test")+"="+a.Status)
	}
	return Result{Status: status, Detail: strings.Join(out, " ")}
}

// lookupName asks the guest's own resolver for name's address and says what
// came, as ask does: "addr:<ip>", a refusal, "timeout", "unreachable", or
// "no-resolver" when the guest has none configured.
func lookupName(name string) string {
	addr, err := resolverAddr(resolvConf)
	if err != nil {
		return "no-resolver"
	}
	msg, id, err := encode("A:"+name+".", "")
	if err != nil {
		return "error"
	}
	got, _ := ask(addr, msg, id, attemptWait)
	return got
}

// holdOpen opens req and reads the response until the far end closes it or
// holdFor passes, and says which, with the bytes read and the time it took.
func holdOpen(req *http.Request, addrs map[string]string) string {
	ctx, cancel := context.WithTimeout(context.Background(), holdFor)
	defer cancel()
	tr := transport(addrs, &tls.Config{}, false)
	defer tr.CloseIdleConnections()
	if req.Header == nil {
		req.Header = http.Header{} // RoundTrip, unlike a Client, fills nothing in
	}
	start := time.Now()
	resp, err := tr.RoundTrip(req.WithContext(ctx))
	if err != nil {
		return "failed:" + strings.ReplaceAll(dialFailed(err).Status, " ", "-")
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	what := "closed"
	if ctx.Err() != nil {
		what = "open"
	}
	return fmt.Sprintf("%s-%db-%dms", what, n, time.Since(start).Milliseconds())
}

// stream is the connection the guest holds at the allowed canary: when the
// guest opened it and when it ended, as the canary saw them, the first one.
type stream struct {
	mu            sync.Mutex
	opened, ended time.Time
}

func (st *stream) times() (opened, ended time.Time) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.opened, st.ended
}

// serve answers /stream with a byte every 100 ms until the connection ends,
// and any other path at once. The canary's read deadline is lifted for the
// connection, since the guest holds it longer than a request may take.
func (st *stream) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/stream" {
		return
	}
	rc := http.NewResponseController(w)
	rc.SetReadDeadline(time.Time{})
	w.WriteHeader(http.StatusOK)
	rc.Flush()
	st.mu.Lock()
	first := st.opened.IsZero()
	if first {
		st.opened = time.Now()
	}
	st.mu.Unlock()
	if first {
		defer func() {
			st.mu.Lock()
			st.ended = time.Now()
			st.mu.Unlock()
		}()
	}
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-tick.C:
			if _, err := io.WriteString(w, "."); err != nil {
				return
			}
			rc.Flush()
		}
	}
}

// helperKilled runs the guest of holdProbe, waits until the allowed canary
// serves the connection the guest holds (or, atStart, kills at once, while the
// guest is still booting), kills the named helper with SIGKILL, and judges the
// host after: the helper is dead and every process of the session with it,
// the held connection closed within closeWithin, the run over within
// wakeWait, no request at either canary and no question at the judge's
// resolver after the kill, and, if the guest could still speak, its resolver
// answered no name. A guest that held no connection before the kill is an error, not a pass.
func helperKilled(name string, atStart bool) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		// The canaries and the judge's resolver, where the product reaches
		// the test host; the resolver answers both names with the address
		// the canaries listen at.
		var st stream
		allowed, denied := &canary{name: s.Allow[0], respond: st.serve}, &canary{name: s.Deny[0]}
		ns, stop, err := serveTwo(ctx, s, nil, allowed, denied)
		if err != nil {
			return false, "", err
		}
		defer ns.stop()
		defer stop()

		// The guest's run, under a context of this judge's own, so that a
		// run that outlives the helper is cut short before the canaries go.
		rctx, cancel := context.WithCancel(ctx)
		defer cancel()
		type outcome struct {
			out sandbox.Output
			err error
		}
		run := make(chan outcome, 1)
		go func() {
			out, err := s.Exec(rctx, allowed.name, allowed.addr, denied.name, denied.addr)
			run <- outcome{out, err}
		}()
		var over *outcome
		finish := func() *outcome {
			if over == nil {
				cancel()
				o := <-run
				over = &o
			}
			return over
		}
		defer finish()
		said := func() string {
			o := finish()
			switch {
			case o.err != nil:
				return "the run: " + o.err.Error()
			case o.out.Exit != 0:
				return fmt.Sprintf("the run ended with exit %d: %s", o.out.Exit, bytes.TrimSpace(o.out.Stderr))
			}
			r, err := ParseResult(o.out.Stdout)
			if err != nil {
				return "the guest's output: " + err.Error()
			}
			return says(r)
		}

		// A helper the product does not have is known before anything is
		// waited for; the pid that is killed is asked for again at the kill.
		if _, err := s.Helper(ctx, name); err != nil {
			return false, "", err
		}
		if !atStart {
			for deadline := time.Now().Add(bootWait); ; {
				if opened, _ := st.times(); !opened.IsZero() {
					break
				}
				select {
				case o := <-run:
					over = &o
				case <-time.After(20 * time.Millisecond):
				}
				if over != nil || time.Now().After(deadline) {
					return false, "", fmt.Errorf("the guest held no connection to %s before the kill, which a correct product serves (%s served %d requests; the resolver was asked [%s]; %s)",
						allowed.name, allowed.name, len(allowed.requests()), strings.Join(ns.questions(), ", "), said())
				}
			}
		}
		pid, err := s.Helper(ctx, name)
		if err != nil {
			return false, "", err
		}
		if pid <= 1 || pid == os.Getpid() || pid == os.Getppid() {
			return false, "", fmt.Errorf("the adapter names pid %d as the %s", pid, name)
		}
		if alive, err := helperAlive(pid); err != nil || !alive {
			return false, "", fmt.Errorf("the %s (pid %d) is not running before the kill (%v)", name, pid, err)
		}
		pgid, err := processGroup(pid)
		if err != nil {
			return false, "", err
		}
		kin, err := descendants(pid)
		if err != nil {
			return false, "", err
		}
		served, asked := len(allowed.requests()), len(ns.questions())
		killAt := time.Now()
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
			return false, "", fmt.Errorf("kill -9 %d (the %s): %w", pid, name, err)
		}
		for alive := true; alive; time.Sleep(20 * time.Millisecond) {
			if alive, err = helperAlive(pid); err != nil {
				return false, "", err
			}
			if alive && time.Since(killAt) > deathWait {
				return false, "", fmt.Errorf("the %s (pid %d) survived SIGKILL", name, pid)
			}
		}
		// The session must go with it: its processes, the held connection
		// and the run.
		var left []int
		for time.Since(killAt) < wakeWait {
			left = survivors(kin, pgid)
			select {
			case o := <-run:
				over = &o
			default:
			}
			if _, ended := st.times(); len(left) == 0 && over != nil && (atStart || !ended.IsZero()) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		outlived := over == nil
		time.Sleep(settle)
		_, ended := st.times()
		words := said()
		say := " (" + words + ")"
		if len(left) > 0 {
			return false, fmt.Sprintf("after the %s died, %d processes of the session were still running %s later: pids %v%s", name, len(left), wakeWait, left, say), nil
		}
		if outlived {
			return false, fmt.Sprintf("the session's run outlived the %s by %s%s", name, wakeWait, say), nil
		}
		if !atStart {
			switch {
			case ended.IsZero():
				return false, fmt.Sprintf("the connection the guest held to %s was still open %s after the %s died%s", allowed.name, wakeWait, name, say), nil
			case ended.Before(killAt):
				return false, "", fmt.Errorf("the connection the guest held to %s closed before the kill, so nothing was held when the %s died%s", allowed.name, name, say)
			case ended.Sub(killAt) > closeWithin:
				return false, fmt.Sprintf("the connection the guest held to %s stayed open %s after the %s died%s", allowed.name, ended.Sub(killAt).Round(time.Millisecond), name, say), nil
			}
		}
		if n := len(allowed.requests()) - served; n > 0 {
			return false, fmt.Sprintf("after the %s died the guest still reached %s, %d times%s", name, allowed.name, n, say), nil
		}
		if n := len(denied.requests()); n > 0 {
			return false, fmt.Sprintf("after the %s died the guest reached %s, which no policy allows, %d times%s", name, denied.name, n, say), nil
		}
		if qs := ns.questions(); len(qs) > asked {
			return false, fmt.Sprintf("after the %s died, %d questions still reached the judge's resolver: [%s]%s", name, len(qs)-asked, strings.Join(qs[asked:], ", "), say), nil
		}
		if what := answeredAfter(words); what != "" {
			return false, fmt.Sprintf("after the %s died the guest's resolver still answered: %s%s", name, what, say), nil
		}
		closed := "the guest was still booting"
		if !atStart {
			closed = fmt.Sprintf("the connection the guest held closed %s after", ended.Sub(killAt).Round(time.Millisecond))
		}
		return true, fmt.Sprintf("the %s (pid %d) died and took the session's %d other processes with it; %s; no canary and no resolver heard from the guest again%s", name, pid, len(kin), closed, say), nil
	}
}

// below lists the processes under pid in the tree children describes.
func below(children map[int][]int, pid int) []int {
	var out []int
	for queue := []int{pid}; len(queue) > 0; queue = queue[1:] {
		out = append(out, children[queue[0]]...)
		queue = append(queue, children[queue[0]]...)
	}
	return out
}

// survivors lists what is left of a session after its helper's death: the
// processes below the helper, listed before the kill, that still run, and
// any process still in the helper's group, unless that is the judge's own.
func survivors(kin []int, pgid int) []int {
	var out []int
	for _, p := range kin {
		if alive, _ := helperAlive(p); alive {
			out = append(out, p)
		}
	}
	if pgid > 1 && pgid != syscall.Getpgrp() {
		members, _ := groupMembers(pgid)
		for _, p := range members {
			if alive, _ := helperAlive(p); alive && !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out
}

// answeredAfter reads the guest's own account of its resolver after the
// death: an address for either name is a resolver still answering.
func answeredAfter(words string) string {
	for _, f := range strings.Fields(words) {
		if k, v, ok := strings.Cut(f, "="); ok && strings.HasPrefix(k, "after-dns") && strings.HasPrefix(v, "addr:") {
			return f
		}
	}
	return ""
}
