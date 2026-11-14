// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/omkhar/workcell/v2/escape/sandbox"
)

// SPEC I12, through the self-rollback of B9 and B10. The operator installs a provider layer and runs it by name, `workcell run claude`. An Exit frame of
// error text that is the guest's first frame passes for the init's own word that the command could not start, and the host acts on it outside the
// session: the layer is set aside, and every later session runs the version before it, or none. Here the command itself speaks first: the layer's
// binary is the payload, served as the bare executable the real claude pin is, and before it writes a byte it takes the init's connection (pidfd_getfd
// on pid 1, as the channel rows do) and writes that one frame. The layer must still be current for the next session, seen through a second
// `workcell run claude` and, on the host, where the image lies.
const rollbackVersion, noExecText = "5.5.5", "nope"

// rollbackProbe is the layer's claude: "forge" writes the Exit of error text on the init's channel at args[1] before anything else, then lingers;
// "check" says whether a claude is on PATH at all.
func rollbackProbe(args []string) Result {
	switch {
	case len(args) == 1 && args[0] == "check":
		if path, err := exec.LookPath(layerAgent); err == nil {
			return Result{Status: "present", Detail: layerAgent + "=" + path}
		}
		return Result{Status: "missing", Detail: layerAgent + "=none"}
	case len(args) != 2 || args[0] != "forge":
		return Result{Status: "error", Detail: "want forge and channel address, or check"}
	}
	ch, err := stealChannel(args[1])
	if err != nil {
		return Result{Status: "error", Detail: "take the init's channel: " + err.Error()}
	}
	defer ch.close()
	if _, err := ch.write(frame(typeExit, textTag([]byte(noExecText))), sendWait); err != nil {
		return Result{Status: "unsent", Detail: "first frame: " + err.Error()}
	}
	time.Sleep(shortLinger)
	return Result{Status: "sent", Detail: fmt.Sprintf("an Exit of error text %q as the guest's first frame, still running %s later", noExecText, shortLinger)}
}

// rollbackJudge installs the layer, runs the operator's command once, which forges the first frame, and then has a second session run it again: the
// layer must still run and its image must still be on the host. The hostile run itself is detail, held only to what every hostile run is (hostFault).
func rollbackJudge(ctx context.Context, s Session) (bool, string, error) {
	payload, err := os.ReadFile(s.Payload)
	if err != nil {
		return false, "", err
	}
	cfg, err := certificate("127.0.0.1")
	if err != nil {
		return false, "", err
	}
	src, err := serve(cfg)
	if err != nil {
		return false, "", err
	}
	defer src.stop()
	path, _ := shaped(layerAgent, rollbackVersion)
	src.set(path, whole(payload))
	image, err := s.Install(ctx, sandbox.Layer{Agent: layerAgent, Version: rollbackVersion, URL: src.url + path, Artifact: payload})
	if err != nil {
		return false, "", err
	}
	ch, err := s.Channel(ctx)
	if err != nil {
		return false, "", err
	}
	rctx, cancel := context.WithTimeout(ctx, hangBound)
	defer cancel()
	out, err := s.Exec(rctx, "forge", ch.Addr)
	if err != nil {
		if rctx.Err() != nil && ctx.Err() == nil {
			return false, fmt.Sprintf("the run whose guest forged the first frame did not end within %s", hangBound), nil
		}
		return false, "", err
	}
	hostile := fmt.Sprintf("the hostile run: exit %d: %s", out.Exit, firstLine(out.Stderr))
	if why := hostFault(out); why != "" {
		return false, hostile + ": " + why, nil
	}
	two, err := s.Another(nil)
	if err != nil {
		return false, "", err
	}
	after, err := two.Exec(ctx, "check")
	if err != nil {
		return false, "", err
	}
	kept, gone := "", false
	if image != "" {
		_, err := os.Stat(image)
		if gone, kept = err != nil, "; the layer image is still on the host"; gone {
			kept = fmt.Sprintf("; the layer image %s is gone from the host", filepath.Base(image))
		}
	}
	r, perr := ParseResult(after.Stdout)
	prefix := fmt.Sprintf("after the guest's forged first frame, a second `workcell run %s` ", layerAgent)
	switch {
	case after.Exit != 0 || perr != nil:
		return false, fmt.Sprintf("%scould not run the layer the operator installed: exit %d: %s%s (%s)", prefix, after.Exit, firstLine(after.Stderr), kept, hostile), nil
	case r.Status != "present":
		return false, fmt.Sprintf("%sran, but the layer's %s is gone: %s%s (%s)", prefix, layerAgent, r.Detail, kept, hostile), nil
	case gone:
		return false, fmt.Sprintf("%sstill ran, but the host dropped the layer's image%s (%s)", prefix, kept, hostile), nil
	}
	return true, fmt.Sprintf("the layer the operator installed is still current after the guest's forged first frame: the second session says %s%s (%s)", r.Detail, kept, hostile), nil
}
