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

// SPEC I12, through the self-rollback of B9 and B10. The operator installs a
// provider layer and runs the provider by name, `workcell run claude`. The
// host takes an Exit frame that arrives as the guest's first frame, carrying
// an error text, for the init's own word that the command could not start,
// and acts on it outside the session: it sets the layer aside, so that every
// later session runs the version before it, or none. Root in the guest
// speaks first: the command itself, before it writes a byte, takes the
// init's connection (pidfd_getfd on pid 1, as the channel rows do) and
// writes that one frame. Nothing the guest says may change what the host
// has installed: the layer must still be current for the next session,
// which the judge sees through the product's own surface, a second
// `workcell run claude`, and on the host, where the image lies.
//
// The layer's binary is the payload itself, served as the bare executable
// the real claude pin is, so that the command the operator runs by name is
// the attacker, with no stdin and no output before the forged frame.
const (
	rollbackVersion = "5.5.5" // the version the operator installs
	noExecText      = "nope"  // the forged Exit's error text
)

// rollbackProbe is the command the operator ran, as the layer's claude: as
// "forge" it takes the init's channel at args[1] and writes one Exit frame
// of error text before anything else, then lingers; as "check" it says
// whether the layer's claude is on PATH at all.
func rollbackProbe(args []string) Result {
	if len(args) == 0 {
		return Result{Status: "error", Detail: "want forge and channel address, or check"}
	}
	switch args[0] {
	case "check":
		path, err := exec.LookPath(layerAgent)
		if err != nil {
			return Result{Status: "missing", Detail: layerAgent + "=none"}
		}
		return Result{Status: "present", Detail: layerAgent + "=" + path}
	case "forge":
		if len(args) != 2 {
			return Result{Status: "error", Detail: "want forge and channel address"}
		}
		ch, err := stealChannel(args[1])
		if err != nil {
			return Result{Status: "error", Detail: "take the init's channel: " + err.Error()}
		}
		defer ch.close()
		b := frame(typeExit, textTag([]byte(noExecText)))
		if _, err := ch.write(b, sendWait); err != nil {
			return Result{Status: "unsent", Detail: "first frame: " + err.Error()}
		}
		time.Sleep(shortLinger)
		return Result{Status: "sent", Detail: fmt.Sprintf("an Exit of error text %q as the guest's first frame, still running %s later", noExecText, shortLinger)}
	}
	return Result{Status: "error", Detail: "unknown kind " + args[0]}
}

// rollbackJudge installs the layer, runs the operator's command once, which
// forges the first frame, and then has a second session run the same command:
// the layer the operator installed must still run, and its image must still
// be on the host. What the hostile run itself returned is detail, held only
// to what every hostile run is (hostFault): the finding is the host state after.
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
	kept := ""
	if image != "" {
		if _, err := os.Stat(image); err != nil {
			kept = fmt.Sprintf("; the layer image %s is gone from the host", filepath.Base(image))
		} else {
			kept = "; the layer image is still on the host"
		}
	}
	r, perr := ParseResult(after.Stdout)
	switch {
	case after.Exit != 0 || perr != nil:
		return false, fmt.Sprintf("after the guest's forged first frame, a second `workcell run %s` could not run the layer the operator installed: exit %d: %s%s (%s)", layerAgent, after.Exit, firstLine(after.Stderr), kept, hostile), nil
	case r.Status != "present":
		return false, fmt.Sprintf("after the guest's forged first frame, a second `workcell run %s` ran, but the layer's %s is gone: %s%s (%s)", layerAgent, layerAgent, r.Detail, kept, hostile), nil
	case image != "" && kept != "; the layer image is still on the host":
		return false, fmt.Sprintf("after the guest's forged first frame, a second `workcell run %s` still ran, but the host dropped the layer's image%s (%s)", layerAgent, kept, hostile), nil
	}
	return true, fmt.Sprintf("the layer the operator installed is still current after the guest's forged first frame: the second session says %s%s (%s)", r.Detail, kept, hostile), nil
}
