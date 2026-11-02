// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"
)

// reachable is the sandbox the I11 tests want: one allowed name and one
// denied, both resolving to the test host, where the judge's canaries listen.
var reachable = Want{Allow: []string{"allowed.escape.test"}, Deny: []string{"denied.escape.test"}}

// reachProbe fetches https://<name>:<port>/ for each name and address pair
// in args, a second time after a pause when the first attempt fails, and
// reports what each name gave.
func reachProbe(args []string) Result {
	if len(args) < 2 || len(args)%2 != 0 {
		return Result{Status: "error", Detail: "want name and address pairs"}
	}
	addrs := map[string]string{}
	for i := 0; i < len(args); i += 2 {
		addrs[args[i]] = args[i+1]
	}
	status := "unreached"
	var out []string
	for i := 0; i < len(args); i += 2 {
		name := args[i]
		t := targets{addrs: addrs}
		r := report(fetch(t.get(name, "/reach"), addrs, &tls.Config{}, false))
		if r.Status != "served" {
			time.Sleep(300 * time.Millisecond)
			r = report(fetch(t.get(name, "/retry"), addrs, &tls.Config{}, false))
		}
		if r.Status == "served" {
			status = "served"
		}
		out = append(out, name+"="+r.Status)
	}
	return Result{Status: status, Detail: strings.Join(out, " ")}
}

// helperKilled has the guest reach the allowed name, kills the named helper
// with SIGKILL, as a crash would, and has the guest try the allowed name and
// a denied one. The invariant holds only if the guest reached the allowed
// name before, the helper existed and died, and no canary saw the guest after.
func helperKilled(name string) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		allowed, err := listen(s.Allow[0], nil, nil)
		if err != nil {
			return false, "", err
		}
		defer allowed.stop()
		denied, err := listen(s.Deny[0], nil, nil)
		if err != nil {
			return false, "", err
		}
		defer denied.stop()
		r, err := s.Run(allowed.name, allowed.addr)
		if err != nil {
			return false, "", err
		}
		if len(allowed.requests()) == 0 {
			return false, "", fmt.Errorf("the guest did not reach %s before the kill, which a correct product serves (guest says %s: %s)", allowed.name, r.Status, r.Detail)
		}
		pid, err := s.Helper(ctx, name)
		if err != nil {
			return false, "", err
		}
		if pid <= 1 || pid == os.Getpid() {
			return false, "", fmt.Errorf("the adapter names pid %d as the %s", pid, name)
		}
		if alive, err := helperAlive(pid); err != nil || !alive {
			return false, "", fmt.Errorf("the %s (pid %d) is not running before the kill (%v)", name, pid, err)
		}
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
			return false, "", fmt.Errorf("kill -9 %d (the %s): %w", pid, name, err)
		}
		alive := true
		for start := time.Now(); alive && time.Since(start) < 3*time.Second; time.Sleep(20 * time.Millisecond) {
			if alive, err = helperAlive(pid); err != nil {
				return false, "", err
			}
		}
		if alive {
			return false, "", fmt.Errorf("the %s (pid %d) survived SIGKILL", name, pid)
		}
		served := len(allowed.requests())
		r, err = s.Run(allowed.name, allowed.addr, denied.name, denied.addr)
		if err != nil {
			return false, "", err
		}
		say := fmt.Sprintf(" (guest says %s: %s)", r.Status, r.Detail)
		if n := len(allowed.requests()) - served; n > 0 {
			return false, fmt.Sprintf("after the %s died the guest still reached %s, %d times%s", name, allowed.name, n, say), nil
		}
		if n := len(denied.requests()); n > 0 {
			return false, fmt.Sprintf("after the %s died the guest reached %s, which no policy allows, %d times%s", name, denied.name, n, say), nil
		}
		return true, fmt.Sprintf("the %s (pid %d) died and no canary saw the guest after%s", name, pid, say), nil
	}
}
