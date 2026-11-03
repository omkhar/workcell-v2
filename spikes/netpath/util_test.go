// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package netpath

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The inputs, URLs and digests of internal/vmm/firecracker's tests (and spikes/fcch).
const (
	fcURL     = "https://github.com/firecracker-microvm/firecracker/releases/download/v1.17.0/firecracker-v1.17.0-x86_64.tgz"
	fcSHA256  = "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558"
	fcMember  = "release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64"
	kernelURL = "https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.14/x86_64/vmlinux-6.1.155"
	kernelSHA = "e41c7048bd2475e7e788153823fcb9166a7e0b78c4c443bd6446d015fa735f53"
)

// needKVM skips where no guest can boot.
func needKVM(t *testing.T) {
	t.Helper()
	if runtime.GOARCH != "amd64" {
		t.Skip("the pinned Firecracker and kernel are linux/amd64 builds")
	}
	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err != nil {
		t.Skipf("no usable /dev/kvm: %v", err)
	} else {
		_ = f.Close()
	}
}

// shortDir is a fresh directory whose vsock socket paths fit sun_path.
func shortDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if len(dir) > 80 {
		var err error
		if dir, err = os.MkdirTemp("", "wc"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
	}
	return dir
}

// download fetches url into dir/name and compares its SHA-256 with want.
func download(dir, url, name, want string) (string, error) {
	path := filepath.Join(dir, name)
	c := http.Client{Timeout: 3 * time.Minute}
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(f, h), resp.Body)
	if err = errors.Join(err, f.Close()); err != nil {
		return "", err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return "", fmt.Errorf("%s: sha256 %s, pinned %s", name, got, want)
	}
	return path, nil
}

// untar writes the one regular member of a gzipped tar to out, executable.
func untar(archive, member, out string) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err != nil {
			return fmt.Errorf("%s in %s: %w", member, archive, err)
		}
		if h.Name != member || h.Typeflag != tar.TypeReg {
			continue
		}
		w, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o755)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, tr)
		return errors.Join(err, w.Close())
	}
}

// guestInitramfs builds ./cmd/guest for the guest and writes it as /init of an
// uncompressed newc cpio in dir.
func guestInitramfs(dir string) (string, error) {
	bin := filepath.Join(dir, "guest")
	cmd := exec.Command("go", "build", "-trimpath", "-o", bin, "./cmd/guest")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH=amd64")
	if o, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("go build ./cmd/guest: %v\n%s", err, o)
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "initramfs.cpio")
	return path, os.WriteFile(path, append(newc("init", 0o100755, b), newc("TRAILER!!!", 0, nil)...), 0o644)
}

// newc returns one entry of a "newc" cpio archive: the 110-byte header, the
// name and its NUL padded to 4, then the data padded to 4.
func newc(name string, mode uint32, data []byte) []byte {
	var b bytes.Buffer
	fields := []uint32{1, mode, 0, 0, 1, 0, uint32(len(data)), 0, 0, 0, 0, uint32(len(name) + 1), 0}
	b.WriteString("070701")
	for _, f := range fields { // ino mode uid gid nlink mtime filesize devmajor devminor rdevmajor rdevminor namesize check
		fmt.Fprintf(&b, "%08X", f)
	}
	b.WriteString(name)
	b.WriteByte(0)
	b.Write(make([]byte, -b.Len()&3))
	b.Write(data)
	b.Write(make([]byte, -b.Len()&3))
	return b.Bytes()
}

// procs returns the pids whose /proc/<pid>/<file> (NULs shown as blanks) matches.
func procs(file string, match func(string) bool) (pids []string) {
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/" + file)
		if err == nil && match(strings.ReplaceAll(strings.TrimRight(string(b), "\x00\n"), "\x00", " ")) {
			pids = append(pids, e.Name())
		}
	}
	return pids
}

// kib reads a "Key:   1234 kB" line of a /proc file, in KiB.
func kib(path, key string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return kibValue(string(b), key)
}

func kibValue(text, key string) (int64, error) {
	for _, l := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(l, key+":"); ok {
			return strconv.ParseInt(strings.TrimSuffix(strings.TrimSpace(v), " kB"), 10, 64)
		}
	}
	return 0, fmt.Errorf("no %s", key)
}

// hostIPv4 is the host's own first non-loopback IPv4 address, as escape/suite's resolve finds it.
func hostIPv4() (string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLinkLocalUnicast() {
				return ipn.IP.String(), nil
			}
		}
	}
	return "", errors.New("the host has no non-loopback IPv4 address for a canary")
}

// The DNS codec below is escape/suite/dns.go's parseDNSQuery, copied: the
// bytes come from the guest.
const (
	dnsTypeA   = 1
	dnsClassIN = 1
	maxLabel   = 63
	maxName    = 255
	canaryName = "canary.test."
)

type dnsQuestion struct {
	ID   uint16
	Name string
	Type uint16
}

func parseDNSQuery(b []byte) (dnsQuestion, bool) {
	if len(b) < 12 || b[2]&0x80 != 0 || binary.BigEndian.Uint16(b[4:]) == 0 {
		return dnsQuestion{}, false
	}
	var name strings.Builder
	i := 12
	for {
		if i >= len(b) {
			return dnsQuestion{}, false
		}
		n := int(b[i])
		i++
		if n == 0 {
			break
		}
		if n > maxLabel || i+n > len(b) || name.Len()+n+1 > maxName {
			return dnsQuestion{}, false
		}
		for _, c := range b[i : i+n] {
			if c <= ' ' || c > '~' || c == '.' {
				return dnsQuestion{}, false
			}
		}
		name.Write(b[i : i+n])
		name.WriteByte('.')
		i += n
	}
	if name.Len() == 0 || i+4 > len(b) || binary.BigEndian.Uint16(b[i+2:]) != dnsClassIN {
		return dnsQuestion{}, false
	}
	return dnsQuestion{ID: binary.BigEndian.Uint16(b), Name: name.String(), Type: binary.BigEndian.Uint16(b[i:])}, true
}

// dnsAnswer answers a query: canary.test. A is 127.0.0.1, its other types have
// no answer, every other name is NXDOMAIN. Nil for what is not a query.
func dnsAnswer(q []byte) []byte {
	qq, ok := parseDNSQuery(q)
	if !ok {
		return nil
	}
	b := append([]byte{q[0], q[1], 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0}, q[12:12+len(qq.Name)+1+4]...)
	switch {
	case !strings.EqualFold(qq.Name, canaryName):
		b[3] |= 3 // NXDOMAIN
	case qq.Type == dnsTypeA:
		b[7] = 1
		b = append(b, 0xc0, 12, 0, dnsTypeA, 0, dnsClassIN, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1)
	}
	return b
}
