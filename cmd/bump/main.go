// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Command bump moves the rows of pins/ to their next verified release: once a
// day, at most one pull request per class, merged when the gate is green (B13).
// With -dry-run it prints the plan and posts and writes nothing; -channel signs channel.json offline.
package main

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/omkhar/workcell/v2/internal/advisory"
	"github.com/omkhar/workcell/v2/internal/bump"
	"github.com/omkhar/workcell/v2/internal/channel"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	t := bump.Tool{Pins: "pins", Upstream: http.DefaultClient, OSV: advisory.OSV, PinTime: 3 * time.Minute, Now: time.Now(), Out: os.Stdout,
		GitHub: bump.GitHub{Client: &http.Client{Timeout: time.Minute}}}
	code := run(ctx, os.Args[1:], os.Getenv, t, os.Stderr)
	stop()
	os.Exit(code)
}

// run reads the flags and the GitHub Actions environment into t and runs it.
// It exits 2 on refused data and 1 on a failed step.
func run(ctx context.Context, args []string, getenv func(string) string, t bump.Tool, stderr io.Writer) int {
	fs := flag.NewFlagSet("bump", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&t.DryRun, "dry-run", false, "print the plan; post and write nothing")
	fs.StringVar(&t.GitHub.API, "api", cmp.Or(getenv("GITHUB_API_URL"), "https://api.github.com"), "the GitHub API root")
	fs.StringVar(&t.GitHub.Repo, "repo", getenv("GITHUB_REPOSITORY"), "the repository, owner/name")
	newest := fs.Bool("newest", false, "print the freshness report, rewrite each guest row at upstream's newest stable release, name the pins that miss P7, and exit 1 when verification fails")
	out := fs.String("channel", "", "write the signed channel.json here; the arguments are ed25519 PKCS#8 PEM key files")
	if fs.Parse(args) != nil || (*out == "") != (fs.NArg() == 0) {
		return 2
	}
	t.GitHub.Token = getenv("GITHUB_TOKEN")
	step := t.Run
	switch {
	case *out != "":
		step = func(context.Context) error { return publish(*out, fs.Args(), t) }
	case *newest:
		step = t.Newest
	}
	err := step(ctx)
	if err == nil {
		return 0
	}
	fmt.Fprintln(stderr, "bump:", err)
	if errors.As(err, new(bump.Refused)) {
		return 2
	}
	return 1
}

// publish writes the rows as channel.json signed by each key file, only after Verify accepts it under each key alone (B7).
func publish(path string, keyFiles []string, t bump.Tool) error {
	rows, err := bump.Load(t.Pins)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.Version != "" && r.Released.IsZero() {
			return bump.Refused("pin " + r.Name + " has no release time")
		}
	}
	var keys []ed25519.PrivateKey
	for _, f := range keyFiles {
		b, _ := os.ReadFile(f)
		blk, _ := pem.Decode(b)
		k, err := x509.ParsePKCS8PrivateKey(cmp.Or(blk, new(pem.Block)).Bytes)
		key, ok := k.(ed25519.PrivateKey)
		if err != nil || !ok {
			return bump.Refused("key file " + f + " is not an ed25519 PKCS#8 PEM key")
		}
		keys = append(keys, key)
	}
	body, _ := json.Marshal(channel.Build(rows, t.Now))
	raw, _ := channel.Sign(body, keys) // a failure leaves nothing for Verify to accept
	var ids []string
	for _, k := range keys {
		pub := channel.Key{Public: k.Public().(ed25519.PublicKey), NotAfter: t.Now.Add(14 * 24 * time.Hour)}
		if _, err := channel.Verify(raw, []channel.Key{pub}, t.Now, 0); err != nil {
			return bump.Refused("channel.json does not verify: " + err.Error())
		}
		ids = append(ids, pub.ID())
	}
	if err = os.WriteFile(path, raw, 0o644); err == nil {
		fmt.Fprintln(t.Out, "channel serial", t.Now.Unix(), "keys", strings.Join(ids, " "))
	}
	return err
}
