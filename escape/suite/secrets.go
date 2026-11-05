// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/omkhar/workcell/v2/escape/sandbox"
)

// The I5 probe is an agent gone rogue: root in the guest, it looks for the
// real credential everywhere a naive sandbox leaves one. It knows the format
// of the secret, as an attacker knows a provider's key prefix, not its value:
// it reports every value of that shape it finds and where, and the judge,
// which chose the value, says whether any of them is real. A placeholder
// found this way is no leak.

const (
	secretPrefix = "sk-escape-"
	secretHex    = 24 // hex digits after the prefix
	secretLen    = len(secretPrefix) + secretHex

	diskBudget = 5 * time.Second // for the processes' environment and the disk
	memBudget  = 3 * time.Second // for process memory
	fileLimit  = 1 << 20         // bytes read of one file
	diskLimit  = 256 << 20       // bytes read from disk in all
	fileQuota  = 50000           // files read in all
	maxValues  = 5               // distinct values the result names; more is marked
	procLimit  = 512 << 20       // bytes read of one process's memory
	memLimit   = 1 << 30         // bytes read of process memory in all
	readChunk  = 1 << 20
)

// NewSecret makes a fresh secret bound to host, in the header boundHeader,
// for the runner to put in a session's Config when a test wants one; narrow
// binds it to narrowMethod requests under narrowPath alone.
func NewSecret(host string, narrow bool) sandbox.Secret {
	sec := sandbox.Secret{Name: "escape", Value: secretPrefix + newToken()[:secretHex], Host: host, Header: boundHeader, Env: "ESCAPE_API_KEY"}
	if narrow {
		sec.Method, sec.Path = narrowMethod, narrowPath
	}
	return sec
}

const (
	boundHeader  = "x-api-key"
	narrowMethod = "POST"
	narrowPath   = "/v1/"
)

// withSecret is the sandbox the I5 tests want: a workspace, two allowed
// names, bare, a secret bound to the first, the judge as the host's
// resolver and the host side in a network of its own, where the judge
// holds the one address both names resolve to and serves a canary for
// each at port 443 (twoNames). The guest's view of the names is given to
// each probe as a literal address beside the name. narrowed binds the
// secret to one method and path as well.
var (
	withSecret = Want{Workspace: true, Allow: []string{"bound.escape.test", "other.escape.test"}, Resolver: judgeResolver, Isolated: true, Secret: true}
	narrowed   = Want{Workspace: true, Allow: withSecret.Allow, Resolver: judgeResolver, Isolated: true, Secret: true, Narrow: true}
)

// findSecrets returns every secret-shaped value in b, in order, once each.
func findSecrets(b []byte) []string {
	var out []string
	for {
		i := bytes.Index(b, []byte(secretPrefix))
		if i < 0 {
			return out
		}
		b = b[i:]
		if len(b) >= secretLen && isHex(b[len(secretPrefix):secretLen]) && (len(b) == secretLen || !isHexByte(b[secretLen])) {
			v := string(b[:secretLen])
			if !slices.Contains(out, v) {
				out = append(out, v)
			}
		}
		b = b[len(secretPrefix):]
	}
}

func isHex(b []byte) bool { return all(b, isHexByte) }
func isHexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f'
}

// scan is one run of the probe: what it found, and how far it got.
type scan struct {
	hits     map[string]string // value -> where it was first seen
	order    []string          // values in the order first seen
	procs    int               // processes whose environment and arguments were read
	files    int               // files read
	mem      int64             // bytes of process memory read
	cut      []string          // phases a budget cut short
	deadline time.Time
}

// note records the secret-shaped values in b and says whether there were any.
func (s *scan) note(b []byte, where string) bool {
	found := findSecrets(b)
	for _, v := range found {
		if _, ok := s.hits[v]; !ok {
			s.order = append(s.order, v)
			s.hits[v] = where
		}
	}
	return len(found) > 0
}

// spent says whether the phase is over, by its own limit or the deadline,
// and records which phases were cut.
func (s *scan) spent(phase string, limit bool) bool {
	if !limit && !time.Now().After(s.deadline) {
		return false
	}
	if !slices.Contains(s.cut, phase) {
		s.cut = append(s.cut, phase)
	}
	return true
}

// secretProbe scans the environment and arguments of every process it can
// see, the disk, and process memory: every process in its own pid namespace,
// then a few ancestors nearest first (the agent that launched it holds what
// the host gave it), stopping at the first ancestor that holds a hit. What
// its own environment holds as the credential (args[1] names the variable)
// comes first in the result, then the values, so that the line's bound
// (maxDetail) can cut only where they were seen; a sixth value is marked
// with "+".
func secretProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want the export path and the credential variable"}
	}
	s := &scan{hits: map[string]string{}, deadline: time.Now().Add(diskBudget)}
	pids := listPids()
	for _, pid := range pids {
		for _, f := range []string{"environ", "cmdline"} {
			if b, err := readPrefix(fmt.Sprintf("/proc/%d/%s", pid, f), fileLimit); err == nil {
				s.note(b, map[string]string{"environ": "env", "cmdline": "argv"}[f]+":"+strconv.Itoa(pid))
			}
		}
		s.procs++
	}
	// Where a session leaves things first, then the rest of the disk.
	dirs := []string{"/tmp", "/var/tmp", "/dev/shm", "/run", "/etc", "/var/log", "/var/lib", "/root", "/home", "/opt", "/srv", "/mnt", "/"}
	if args[0] != "" {
		dirs = append([]string{args[0]}, dirs...)
	}
	s.disk(dirs)
	s.deadline = time.Now().Add(memBudget)
	s.memory(pids)
	detail := "env=" + clean(cmp.Or(os.Getenv(args[1]), "unset"), 40, isToken, '?') + " "
	if n := len(s.order); n > 0 {
		values := s.order[:min(n, maxValues)]
		detail += "found=" + strings.Join(values, " ")
		if n > maxValues {
			detail += "+"
		}
		detail += " "
	}
	detail += fmt.Sprintf("procs=%d files=%d mem=%dMiB", s.procs, s.files, s.mem>>20)
	if len(s.cut) > 0 {
		detail += " cut=" + strings.Join(s.cut, ",")
	}
	for _, v := range s.order {
		detail += " " + v[len(secretPrefix):][:6] + "@" + s.hits[v]
	}
	return Result{Status: "scanned", Detail: detail}
}

func listPids() []int {
	es, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var pids []int
	for _, e := range es {
		if pid, err := strconv.Atoi(e.Name()); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

// readPrefix reads up to n bytes of a file, however long it says it is.
func readPrefix(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, int64(n)))
}

// disk reads the first fileLimit bytes of every regular file under dirs, in
// order, until the budgets run out. Links are not followed; the kernel's
// views of itself are not files, and a directory walked once is not walked
// again from a later root.
func (s *scan) disk(dirs []string) {
	var read int64
	for i, dir := range dirs {
		filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() && path != dir && (slices.Contains(dirs[:i], path) || path == "/proc" || path == "/sys" || path == "/dev") {
				return filepath.SkipDir
			}
			if !d.Type().IsRegular() {
				return nil
			}
			if s.spent("disk", s.files >= fileQuota || read >= diskLimit) {
				return filepath.SkipAll
			}
			b, err := readPrefix(path, fileLimit)
			if err != nil {
				return nil
			}
			s.files++
			read += int64(len(b))
			s.note(b, "disk:"+path)
			return nil
		})
	}
}

// memory reads the anonymous writable mappings of the processes that share
// the probe's pid namespace, then of its ancestors, nearest first. The walk
// up stops at the first hit and after ancestors levels: on a host that lends
// itself to the control adapter, what launched the runner is not a target.
const ancestors = 3

func (s *scan) memory(pids []int) {
	// Not os.Getpid: /proc may belong to a wider pid namespace than the probe's.
	link, _ := os.Readlink("/proc/self")
	self, _ := strconv.Atoi(link)
	ns, _ := os.Readlink("/proc/self/ns/pid")
	for _, pid := range pids {
		if pid == self {
			continue
		}
		if l, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/pid", pid)); err == nil && l == ns {
			s.process(pid)
		}
	}
	pid := parent(self)
	for i := 0; i < ancestors && pid > 1; i++ {
		if hit, spent := s.process(pid); hit || spent {
			return
		}
		pid = parent(pid)
	}
}

func parent(pid int) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	_, after, ok := strings.Cut(string(b), "PPid:")
	if !ok {
		return 0
	}
	ppid, _ := strconv.Atoi(strings.TrimSpace(strings.SplitN(after, "\n", 2)[0]))
	return ppid
}

// process reads one process's memory, up to its share. It reports whether it
// found anything and whether the whole budget is spent.
func (s *scan) process(pid int) (hit, spent bool) {
	maps, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return false, false
	}
	defer maps.Close()
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return false, false
	}
	defer mem.Close()
	comm, _ := readPrefix(fmt.Sprintf("/proc/%d/comm", pid), 16)
	where := fmt.Sprintf("mem:%d(%s)", pid, strings.TrimSpace(string(comm)))
	var read int64
	buf := make([]byte, readChunk+secretLen)
	sc := bufio.NewScanner(maps)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 5 || f[1][0] != 'r' || f[1][1] != 'w' || f[4] != "0" || len(f) > 5 && f[5] != "[heap]" && f[5] != "[stack]" && !strings.HasPrefix(f[5], "[anon") {
			continue // not an anonymous writable mapping: not heap, stack or arena
		}
		lo, hi, ok := strings.Cut(f[0], "-")
		start, err1 := strconv.ParseInt(lo, 16, 64)
		end, err2 := strconv.ParseInt(hi, 16, 64)
		if !ok || err1 != nil || err2 != nil {
			continue
		}
		for off := start; off < end; off += readChunk {
			if s.spent("mem", s.mem >= memLimit) {
				return hit, true
			}
			if read >= procLimit {
				return hit, false
			}
			n, _ := mem.ReadAt(buf[:min(int64(len(buf)), end-off)], off)
			if n > 0 {
				hit = s.note(buf[:n], where) || hit
				read += int64(n)
				s.mem += int64(n)
			}
		}
	}
	return hit, false
}

// secretJudge binds a fresh secret to the session and fails if the guest's
// scan turns the real value up anywhere, or if the guest's own environment
// holds no credential at all: it is to hold a placeholder, which it then
// uses (SPEC A4). A scan that found more values than it could name proves
// nothing either way.
func secretJudge(ctx context.Context, s Session) (bool, string, error) {
	r, err := s.Run(s.Guest, s.Secret.Env)
	if err != nil {
		return false, "", err
	}
	if r.Status != "scanned" {
		return false, "", fmt.Errorf("the probe did not scan: %s: %s", r.Status, r.Detail)
	}
	if strings.Contains(r.Detail, s.Secret.Value) {
		return false, "the guest holds the real secret: " + r.Detail, nil
	}
	if strings.HasPrefix(r.Detail, "env=unset ") {
		return false, "the guest was given no placeholder in " + s.Secret.Env + ": " + r.Detail, nil
	}
	if strings.Contains(r.Detail, "+ ") {
		return false, "", fmt.Errorf("the guest found more secret-shaped values than it can name: %s", r.Detail)
	}
	return true, "the real secret is not in the guest: " + r.Detail, nil
}
