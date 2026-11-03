// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

//go:build linux

package netpath

import (
	"bytes"
	"net/netip"
	"slices"
	"testing"

	"github.com/omkhar/workcell/v2/spikes/netpath/relay"
)

func TestHeader(t *testing.T) {
	for _, tc := range []struct {
		name  string
		proto byte
		dst   string
	}{
		{"ipv4", relay.TCP, "198.51.100.7:443"},
		{"ipv6", relay.TCP, "[2001:db8::7]:80"},
		{"udp", relay.UDP, "127.0.0.1:53"},
	} {
		h := relay.Header{Proto: tc.proto, Dst: netip.MustParseAddrPort(tc.dst)}
		b := h.Encode()
		got, err := relay.Decode(b)
		if err != nil || got != h || len(b) != relay.HeaderLen {
			t.Errorf("%s: Decode(Encode) = %v, %v from % x", tc.name, got, err, b)
		}
	}
	good := relay.Header{Proto: relay.TCP, Dst: netip.MustParseAddrPort("1.2.3.4:5")}.Encode()
	for _, tc := range []struct {
		name string
		b    []byte
	}{
		{"short", good[:19]},
		{"long", append(slices.Clone(good), 0)},
		{"version", append([]byte{2}, good[1:]...)},
		{"proto", append([]byte{1, 1}, good[2:]...)},
		{"empty", nil},
	} {
		if h, err := relay.Decode(tc.b); err == nil {
			t.Errorf("%s: Decode accepted % x as %v", tc.name, tc.b, h)
		}
	}
}

func TestFrame(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want []byte
		ok   bool
	}{
		{"empty", []byte{0, 0}, []byte{}, true},
		{"three", []byte{0, 3, 'a', 'b', 'c', 'x'}, []byte("abc"), true},
		{"short length", []byte{0}, nil, false},
		{"short body", []byte{0, 4, 'a'}, nil, false},
	} {
		got, err := relay.ReadFrame(bytes.NewReader(tc.in))
		if (err == nil) != tc.ok || tc.ok && !bytes.Equal(got, tc.want) {
			t.Errorf("%s: ReadFrame(% x) = %q, %v", tc.name, tc.in, got, err)
		}
	}
	if got, _ := relay.ReadFrame(bytes.NewReader(relay.Frame([]byte("dns")))); string(got) != "dns" {
		t.Errorf("ReadFrame(Frame(dns)) = %q", got)
	}
}

func TestPorts(t *testing.T) {
	for _, tc := range []struct {
		cmdline string
		want    []uint16
		ok      bool
	}{
		{"console=ttyS0 workcell.ports=443,80 quiet", []uint16{443, 80}, true},
		{"workcell.ports=53", []uint16{53}, true},
		{"quiet", nil, false},
		{"workcell.ports=", nil, false},
		{"workcell.ports=443,x", nil, false},
		{"workcell.ports=0", nil, false},
		{"workcell.ports=70000", nil, false},
		{"workcell.ports=443,", nil, false},
	} {
		got, err := relay.Ports(tc.cmdline)
		if (err == nil) != tc.ok || !slices.Equal(got, tc.want) {
			t.Errorf("Ports(%q) = %v, %v", tc.cmdline, got, err)
		}
	}
}

func TestConfig(t *testing.T) {
	text := "CONFIG_NETFILTER=y\n# CONFIG_NF_TABLES is not set\nCONFIG_NETFILTER_XT_TARGET_REDIRECT=m\nCONFIG_HZ=1000\n"
	for sym, want := range map[string]string{"NETFILTER": "y", "NF_TABLES": "n", "NETFILTER_XT_TARGET_REDIRECT": "m",
		"HZ": "1000", "TUN": "absent", "NETFILTER_XT": "absent"} {
		if got := relay.Config(text, sym); got != want {
			t.Errorf("Config(%s) = %q, want %q", sym, got, want)
		}
	}
}

func TestLine(t *testing.T) {
	for _, tc := range []struct {
		pairs []string
		want  map[string]string
	}{
		{[]string{relay.Pair("a", 1), relay.Pair("b", "x y\nz")}, map[string]string{"a": "1", "b": "x_y_z"}},
		{[]string{relay.Pair("k", "v=w"), relay.Pair("e", "")}, map[string]string{"k": "v=w", "e": ""}},
		{[]string{relay.Pair("t", "\x1b[2Jé")}, map[string]string{"t": "_[2J__"}},
		{[]string{"noequals", "=v", relay.Pair("ok", true)}, map[string]string{"ok": "true"}},
	} {
		line := relay.Join(tc.pairs)
		if got := relay.Parse(line); len(got) != len(tc.want) || !mapsEqual(got, tc.want) {
			t.Errorf("Parse(%q) = %v, want %v", line, got, tc.want)
		}
	}
	if got := relay.Clean(string(make([]byte, 500))); len(got) != 160 {
		t.Errorf("Clean of 500 bytes is %d bytes, want 160", len(got))
	}
}

func mapsEqual(a, b map[string]string) bool {
	for k, v := range b {
		if got, ok := a[k]; !ok || got != v {
			return false
		}
	}
	return true
}

func TestStats(t *testing.T) {
	twenty := []int64{20, 1, 19, 2, 18, 3, 17, 4, 16, 5, 15, 6, 14, 7, 13, 8, 12, 9, 11, 10}
	for _, tc := range []struct {
		in           []int64
		p50, lo, max int64
	}{
		{twenty, 10, 1, 20}, // (10+11)/2, integer
		{[]int64{3, 1, 2}, 2, 1, 3},
		{[]int64{7}, 7, 7, 7},
		{[]int64{4, 8}, 6, 4, 8},
		{nil, -1, -1, -1},
	} {
		p50, lo, hi := relay.Stats(tc.in)
		if p50 != tc.p50 || lo != tc.lo || hi != tc.max {
			t.Errorf("Stats(%v) = %d %d %d, want %d %d %d", tc.in, p50, lo, hi, tc.p50, tc.lo, tc.max)
		}
	}
}

func TestKiB(t *testing.T) {
	text := "Name:\tx\nVmRSS:\t   12345 kB\nMemAvailable:   7 kB\n"
	for _, tc := range []struct {
		key  string
		want int64
		ok   bool
	}{{"VmRSS", 12345, true}, {"MemAvailable", 7, true}, {"VmSwap", 0, false}, {"Name", 0, false}} {
		got, err := kibValue(text, tc.key)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("kibValue(%s) = %d, %v", tc.key, got, err)
		}
	}
}

func TestDNSAnswer(t *testing.T) {
	query := func(name string, typ byte) []byte {
		b := []byte{0xbe, 0xef, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		for _, l := range bytes.Split([]byte(name), []byte(".")) {
			b = append(append(b, byte(len(l))), l...)
		}
		return append(b, 0, 0, typ, 0, 1)
	}
	q := query("canary.test", 1)
	question := q[12:]
	for _, tc := range []struct {
		name string
		q    []byte
		want []byte
	}{
		{"A", q, append(append([]byte{0xbe, 0xef, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0}, question...),
			0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1)},
		{"AAAA", query("Canary.Test", 28), append([]byte{0xbe, 0xef, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0}, query("Canary.Test", 28)[12:]...)},
		{"other name", query("example.com", 1), append([]byte{0xbe, 0xef, 0x81, 0x83, 0, 1, 0, 0, 0, 0, 0, 0}, query("example.com", 1)[12:]...)},
		{"a response", append([]byte{0, 0, 0x80}, q[3:]...), nil},
		{"truncated", q[:20], nil},
	} {
		if got := dnsAnswer(tc.q); !bytes.Equal(got, tc.want) {
			t.Errorf("%s: dnsAnswer = % x, want % x", tc.name, got, tc.want)
		}
	}
}
