// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package fcch

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

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
	for _, tc := range []struct {
		name string
		init string
	}{
		{"empty", ""},
		{"one byte", "x"},
		{"three bytes", "abc"},
		{"four bytes", "abcd"},
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

func TestAPI(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "api")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	var gotMethod, gotPath, gotBody string
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotMethod, gotPath, gotBody = r.Method, r.URL.Path, string(b)
		if strings.HasPrefix(r.URL.Path, "/bad") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"fault_message":"nope"}`)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	cli := newAPI(sock)
	for _, tc := range []struct {
		name, path string
		body       any
		errHas     string
	}{
		{"204", "/machine-config", map[string]any{"vcpu_count": 2, "smt": false}, ""},
		{"400", "/bad", map[string]any{"x": 1}, "400 Bad Request: {\"fault_message\":\"nope\"}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := cli.put(tc.path, tc.body)
			switch {
			case tc.errHas == "" && err != nil:
				t.Fatal(err)
			case tc.errHas != "" && (err == nil || !strings.Contains(err.Error(), tc.errHas)):
				t.Fatalf("error %v, want it to contain %q", err, tc.errHas)
			}
			want, _ := json.Marshal(tc.body)
			if gotMethod != http.MethodPut || gotPath != tc.path || gotBody != string(want) {
				t.Fatalf("server saw %s %s %s", gotMethod, gotPath, gotBody)
			}
		})
	}
	if err := newAPI(filepath.Join(t.TempDir(), "none")).put("/x", 1); err == nil {
		t.Fatal("PUT to a missing socket succeeded")
	}
}

func TestParseHello(t *testing.T) {
	cmdline := "console=ttyS0 reboot=k wcshare=blk virtio_mmio.device=4K@0xd0000000:5"
	for _, tc := range []struct {
		name, line, token string
		want              map[string]string
	}{
		{"full", "hello abc loopback=err ifaces=lo,eth0 env_leak=no exit=7 cmdline=" + url.QueryEscape(cmdline), "abc",
			map[string]string{"loopback": "err", "ifaces": "lo,eth0", "env_leak": "no", "exit": "7", "cmdline": cmdline}},
		{"short", "hello t9 loopback=ok", "t9", map[string]string{"loopback": "ok"}},
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

func TestSumFor(t *testing.T) {
	sums := "aa  ./LICENSE\nbb  ./firecracker-v1.17.0-x86_64\ncc  ./firecracker-v1.17.0-x86_64.debug\ndd *plain\n"
	for _, tc := range []struct {
		name, want string
		ok         bool
	}{
		{"firecracker-v1.17.0-x86_64", "bb", true},
		{"firecracker-v1.17.0-x86_64.debug", "cc", true},
		{"missing", "", false},
		{"", "", false},
	} {
		if got, ok := sumFor(sums, tc.name); got != tc.want || ok != tc.ok {
			t.Errorf("sumFor(%q) = %q, %t", tc.name, got, ok)
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
	}{
		{"a\nb\nc\n", 2, "b\nc"},
		{"a\nb", 5, "a\nb"},
		{"", 3, ""},
	} {
		if got := tail(tc.in, tc.n); got != tc.want {
			t.Errorf("tail(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}

func TestScanProc(t *testing.T) {
	self := strconv.Itoa(os.Getpid())
	for _, tc := range []struct {
		name, file, has string
		found           bool
	}{
		{"own cmdline", "cmdline", os.Args[0], true},
		{"nothing like this", "cmdline", "no-such-process-" + self + "-fcch", false},
	} {
		pids := scanProc(tc.file, func(s string) bool { return strings.Contains(s, tc.has) })
		found := false
		for _, p := range pids {
			found = found || p == self
		}
		if found != tc.found {
			t.Errorf("%s: pids %v, own pid %s found=%t, want %t", tc.name, pids, self, found, tc.found)
		}
	}
}

func TestExchange(t *testing.T) {
	for _, tc := range []struct {
		name, send string
		wantErr    bool
	}{
		{"line then close", "hello t loopback=err\n", false},
		{"close without a line", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sock := filepath.Join(t.TempDir(), "v_5000")
			ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			sent := make(chan struct{})
			got := exchange(ln, sent)
			c, err := net.Dial("unix", sock)
			if err != nil {
				t.Fatal(err)
			}
			if tc.send != "" {
				if _, err := io.WriteString(c, tc.send); err != nil {
					t.Fatal(err)
				}
				back := make([]byte, len(tc.send))
				if _, err := io.ReadFull(c, back); err != nil || string(back) != tc.send {
					t.Fatalf("echo %q, %v", back, err)
				}
				<-sent
			}
			_ = c.Close()
			e := <-got
			if (e.err != nil) != tc.wantErr || (!tc.wantErr && (e.line != tc.send || e.first.IsZero() || e.done.Before(e.first))) {
				t.Fatalf("exchange: %+v", e)
			}
		})
	}
}

func TestProc(t *testing.T) {
	e := &env{canary: "c"}
	for _, tc := range []struct {
		name, bin string
		args      []string
		kill      bool
		code      int
	}{
		{"exits 0", "true", nil, false, 0},
		{"exits 1", "false", nil, false, 1},
		{"killed", "sleep", []string{"60"}, true, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := e.start(tc.name, tc.bin, nil, tc.args...)
			if err != nil {
				t.Fatal(err)
			}
			if tc.kill {
				if !p.running() {
					t.Fatal("not running")
				}
				p.kill()
			}
			<-p.done
			if p.code != tc.code || p.running() {
				t.Fatalf("code %d, want %d", p.code, tc.code)
			}
		})
	}
	if _, err := e.start("nope", "/no/such/binary", nil); err == nil {
		t.Fatal("started a missing binary")
	}
}
