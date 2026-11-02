// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

// Package macos is the U-102 spike: boot a Linux microVM on macOS through
// Virtualization.framework (Go binding github.com/Code-Hex/vz/v3) and through
// Apple's container CLI, with the guest, kernels and measurements of U-100 and
// U-101. The VM test runs on darwin/arm64 only; this file is pure logic and
// builds everywhere. Findings are in notes.md.
package macos

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
)

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

// initramfs is an uncompressed cpio holding one executable, /init.
func initramfs(init []byte) []byte {
	return slices.Concat(newc("init", 0o100755, init), newc("TRAILER!!!", 0, nil))
}

// parseHello splits the guest's line "hello <token> k=v ..." into its fields.
func parseHello(line string) (token string, kv map[string]string) {
	kv = map[string]string{}
	f := strings.Fields(line)
	if len(f) < 2 || f[0] != "hello" {
		return "", kv
	}
	for _, p := range f[2:] {
		if k, v, ok := strings.Cut(p, "="); ok {
			kv[k] = v
		}
	}
	if c, err := url.QueryUnescape(kv["cmdline"]); err == nil && c != "" {
		kv["cmdline"] = c
	}
	return f[1], kv
}

// childKV reads vzchild's stdout: one key=value per line, the last one wins.
func childKV(out string) map[string]string {
	kv := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok && k != "" && !strings.Contains(k, " ") {
			kv[k] = v
		}
	}
	return kv
}

// unixNS turns a child's "<key>_unix_ns" value into nanoseconds, 0 if absent.
func unixNS(kv map[string]string, key string) int64 {
	n, _ := strconv.ParseInt(kv[key+"_unix_ns"], 10, 64)
	return n
}

// isImage reports whether b starts like an arm64 Linux Image ("ARM\x64" at 56).
func isImage(b []byte) bool {
	return len(b) >= 60 && string(b[56:60]) == "ARM\x64"
}

// otoolLinks lists the load commands that "otool -L" printed, and those that
// are neither under /usr/lib nor under /System/Library (A6).
func otoolLinks(out string) (all, foreign string) {
	var a, f []string
	for _, l := range strings.Split(out, "\n")[1:] {
		p, _, _ := strings.Cut(strings.TrimSpace(l), " (")
		if p == "" {
			continue
		}
		a = append(a, p)
		if !strings.HasPrefix(p, "/usr/lib/") && !strings.HasPrefix(p, "/System/Library/") {
			f = append(f, p)
		}
	}
	return orNone(a), orNone(f)
}

// entitlements turns "codesign -d --entitlements -" output into key:value pairs.
func entitlements(out string) string {
	var pairs []string
	key := ""
	for _, l := range strings.Split(out, "\n") {
		l = strings.TrimSpace(l)
		switch k, isKey := strings.CutPrefix(l, "[Key] "); {
		case isKey:
			key = k
		case key != "" && strings.HasPrefix(l, "[") && l != "[Value]":
			_, v, _ := strings.Cut(l, "] ")
			pairs = append(pairs, key+":"+v)
			key = ""
		}
	}
	return orNone(pairs)
}

// containerState finds the container with this id in "container ls -a
// --format json" output: its status.state, or "gone".
func containerState(out []byte, id string) (string, error) {
	var list []struct {
		ID     string `json:"id"`
		Status struct {
			State string `json:"state"`
		} `json:"status"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return "", err
	}
	for _, c := range list {
		if c.ID == id {
			return c.Status.State, nil
		}
	}
	return "gone", nil
}

func orNone(v []string) string {
	if len(v) == 0 {
		return "none"
	}
	return strings.Join(v, ",")
}

func stats(v []int64) string {
	s := slices.Sorted(slices.Values(v))
	return fmt.Sprintf("n=%d p50=%d min=%d max=%d", len(s), s[len(s)/2], s[0], s[len(s)-1])
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

// readNewc parses one entry of a newc archive and returns the rest.
func readNewc(t *testing.T, b []byte) (name string, mode uint32, data, rest []byte) {
	t.Helper()
	if len(b) < 110 || string(b[:6]) != "070701" {
		t.Fatalf("no newc header in %q", b[:min(len(b), 8)])
	}
	field := func(i int) int {
		n, err := strconv.ParseUint(string(b[6+8*i:14+8*i]), 16, 32)
		if err != nil {
			t.Fatalf("field %d: %v", i, err)
		}
		return int(n)
	}
	m, filesize, namesize := field(1), field(6), field(11)
	nameEnd := 110 + namesize
	name = strings.TrimRight(string(b[110:nameEnd]), "\x00")
	dataStart := (nameEnd + 3) &^ 3
	dataEnd := dataStart + filesize
	return name, uint32(m), b[dataStart:dataEnd], b[(dataEnd+3)&^3:]
}

func TestInitramfs(t *testing.T) {
	for _, tc := range []struct{ name, init string }{
		{"empty", ""}, {"one byte", "x"}, {"three bytes", "abc"}, {"four bytes", "abcd"},
		{"elf-ish", "\x7fELF\x02\x01\x01\x00\x00"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := initramfs([]byte(tc.init))
			if len(b)%4 != 0 {
				t.Fatalf("archive is %d bytes, not a multiple of 4", len(b))
			}
			name, mode, data, rest := readNewc(t, b)
			if name != "init" || mode != 0o100755 || string(data) != tc.init {
				t.Fatalf("got %q mode %o data %q", name, mode, data)
			}
			name, mode, data, rest = readNewc(t, rest)
			if name != "TRAILER!!!" || mode != 0 || len(data) != 0 || len(rest) != 0 {
				t.Fatalf("trailer: %q mode %o data %q rest %d bytes", name, mode, data, len(rest))
			}
		})
	}
}

func TestParseHello(t *testing.T) {
	cmdline := "console=hvc0 reboot=k panic=-1 quiet wcexit=poweroff wcshare=blk"
	for _, tc := range []struct {
		name, line, token string
		want              map[string]string
	}{
		{"full", "hello abc loopback=err ifaces=lo gateway=none env_leak=no exit=7 cmdline=" + url.QueryEscape(cmdline), "abc",
			map[string]string{"loopback": "err", "ifaces": "lo", "gateway": "none", "env_leak": "no", "exit": "7", "cmdline": cmdline}},
		{"probe", "hello probe loopback=err ifaces=eth0,lo gateway=192.168.64.1", "probe",
			map[string]string{"loopback": "err", "ifaces": "eth0,lo", "gateway": "192.168.64.1"}},
		{"not hello", "bye abc x=y", "", map[string]string{}},
		{"empty", "", "", map[string]string{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, kv := parseHello(tc.line)
			if token != tc.token || len(kv) != len(tc.want) {
				t.Fatalf("got %q %v", token, kv)
			}
			for k, v := range tc.want {
				if kv[k] != v {
					t.Errorf("%s = %q, want %q", k, kv[k], v)
				}
			}
		})
	}
}

func TestChildKV(t *testing.T) {
	out := "start_unix_ns=10\nstate=Running\nfirst_unix_ns=25\nline=hello t a=b\neof_unix_ns=30\nstate=Stopped\nexit_path=poweroff\nnoise\n"
	kv := childKV(out)
	for _, tc := range []struct {
		key, want string
		ns        int64
	}{
		{"line", "hello t a=b", 0}, {"state", "Stopped", 0}, {"exit_path", "poweroff", 0},
		{"start_unix_ns", "10", 0}, {"noise", "", 0},
	} {
		if kv[tc.key] != tc.want {
			t.Errorf("%s = %q, want %q", tc.key, kv[tc.key], tc.want)
		}
	}
	for _, tc := range []struct {
		key  string
		want int64
	}{{"start", 10}, {"first", 25}, {"eof", 30}, {"none", 0}} {
		if got := unixNS(kv, tc.key); got != tc.want {
			t.Errorf("unixNS(%s) = %d, want %d", tc.key, got, tc.want)
		}
	}
}

func TestIsImage(t *testing.T) {
	img := make([]byte, 64)
	copy(img[56:], "ARM\x64")
	for _, tc := range []struct {
		name string
		b    []byte
		want bool
	}{
		{"image", img, true}, {"short", img[:59], false}, {"zeros", make([]byte, 64), false},
		{"elf", append([]byte("\x7fELF"), make([]byte, 60)...), false},
	} {
		if got := isImage(tc.b); got != tc.want {
			t.Errorf("%s: %t, want %t", tc.name, got, tc.want)
		}
	}
}

func TestOtoolLinks(t *testing.T) {
	for _, tc := range []struct{ name, out, all, foreign string }{
		{"nocgo", "/tmp/hello:\n\t/usr/lib/libSystem.B.dylib (compatibility version 1.0.0, current version 1351.0.0)\n",
			"/usr/lib/libSystem.B.dylib", "none"},
		{"framework and rpath", "/x:\n\t/System/Library/Frameworks/Virtualization.framework/Versions/A/Virtualization (compatibility version 1.0.0)\n\t@rpath/libswiftCompatibilitySpan.dylib (compatibility version 0.0.0)\n",
			"/System/Library/Frameworks/Virtualization.framework/Versions/A/Virtualization,@rpath/libswiftCompatibilitySpan.dylib",
			"@rpath/libswiftCompatibilitySpan.dylib"},
		{"not an object", "/x: is not an object file\n", "none", "none"},
	} {
		if all, foreign := otoolLinks(tc.out); all != tc.all || foreign != tc.foreign {
			t.Errorf("%s: %q %q", tc.name, all, foreign)
		}
	}
}

func TestEntitlements(t *testing.T) {
	for _, tc := range []struct{ name, out, want string }{
		{"one", "Executable=/x\n[Dict]\n\t[Key] com.apple.security.virtualization\n\t[Value]\n\t\t[Bool] true\n",
			"com.apple.security.virtualization:true"},
		{"two", "[Dict]\n[Key] a\n[Value]\n[Bool] true\n[Key] b\n[Value]\n[String] x y\n", "a:true,b:x y"},
		{"none", "Executable=/x\n", "none"},
	} {
		if got := entitlements(tc.out); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestContainerState(t *testing.T) {
	out := []byte(`[{"id":"wc-a","status":{"state":"running","startedDate":"x"}},{"id":"wc-b","status":{"state":"stopped"}}]`)
	for _, tc := range []struct {
		name, id, want string
		in             []byte
		err            bool
	}{
		{"running", "wc-a", "running", out, false}, {"stopped", "wc-b", "stopped", out, false},
		{"gone", "wc-c", "gone", out, false}, {"empty", "wc-a", "gone", []byte("[]"), false},
		{"garbage", "wc-a", "", []byte("ID IMAGE"), true},
	} {
		got, err := containerState(tc.in, tc.id)
		if got != tc.want || (err != nil) != tc.err {
			t.Errorf("%s: %q, %v", tc.name, got, err)
		}
	}
}

func TestStatsTail(t *testing.T) {
	for _, tc := range []struct {
		in   []int64
		want string
	}{
		{[]int64{5}, "n=1 p50=5 min=5 max=5"},
		{[]int64{9, 1, 5}, "n=3 p50=5 min=1 max=9"},
		{[]int64{4, 3, 2, 1}, "n=4 p50=3 min=1 max=4"},
		{[]int64{-1, 7}, "n=2 p50=7 min=-1 max=7"},
	} {
		if got := stats(tc.in); got != tc.want {
			t.Errorf("stats(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
	for _, tc := range []struct {
		in   string
		n    int
		want string
	}{{"a\nb\nc\n", 2, "b\nc"}, {"a\nb", 5, "a\nb"}, {"", 3, ""}} {
		if got := tail(tc.in, tc.n); got != tc.want {
			t.Errorf("tail(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}
