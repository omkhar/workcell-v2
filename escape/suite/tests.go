// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Omkhar Arasaratnam

package suite

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/omkhar/workcell/v2/escape/sandbox"
)

// All is the suite. Add a test by adding an entry; no other plumbing exists.
// Every canary a Judge starts is an address of the test host itself: its
// loopback, its own interface address (hostAddr), or an address the judge adds
// to loopback for the test's duration (onLoopback). No packet leaves the host
// (SPEC T8, S12). The guest gets a literal address, never a name.
var All = append([]Test{
	// The first row runs under a policy that opens one port (forwarded), so
	// that an allowlist is shown to open no other port.
	{ID: "I2", Name: "raw-ip-odd-port-tcp4", Probe: dialProbe, Host: tcpCanary("tcp4", hostAddr+":0", ""), Want: forwarded},
	{ID: "I2", Name: "ipv4-mapped-ipv6-tcp", Probe: dialProbe, Host: tcpCanary("tcp4", hostAddr+":0", "::ffff:"+hostAddr)},
	{ID: "I2", Name: "udp4-datagram", Probe: udpProbe, Host: udpCanary(hostAddr+":0", lineToken)},
	{ID: "I2", Name: "quic-initial", Probe: quicProbe, Host: udpCanary(hostAddr+":0", quicToken)},
	{ID: "I2", Name: "icmp-echo", Probe: icmpProbe, Host: icmpJudge},
	// The policy opens one forward port for one name. The guest dials the
	// canary at that very port, as TCP and as UDP: the port is served, but
	// the host resolves the allowed name itself and never dials the address
	// the guest named (I4), and a UDP datagram to a TCP port has no listener.
	{ID: "I2", Name: "allowed-port-raw-ip-tcp4", Probe: dialProbe, Host: tcpCanary("tcp4", hostAddr+":"+forwardPort, ""), Want: forwarded},
	{ID: "I2", Name: "allowed-port-udp4", Probe: udpProbe, Host: udpCanary(hostAddr+":"+forwardPort, lineToken), Want: forwarded},
	// Root in the guest skips the init and speaks the relay's own header to
	// the host end (ADR-003), naming the canary as TCP, as UDP, under a
	// version or proto the host does not serve; and offers a header that
	// never completes, in one short write or a byte at a time.
	{ID: "I2", Name: "relay-header-tcp", Probe: relayProbe, Host: relayCanary("tcp4", hostAddr+":0", "tcp")},
	{ID: "I2", Name: "relay-header-udp", Probe: relayProbe, Host: relayCanary("udp4", hostAddr+":0", "udp")},
	{ID: "I2", Name: "relay-header-bad-version", Probe: relayProbe, Host: relayCanary("tcp4", hostAddr+":0", "version-0", "version-2")},
	{ID: "I2", Name: "relay-header-bad-proto", Probe: relayProbe, Host: relayCanary("tcp4", hostAddr+":0", "proto-0", "proto-1")},
	// The same header names the canary at the port the policy serves, as
	// TCP, which the host hands to the proxy, and as UDP, which it serves on
	// no port but 53. Neither may end at the address in the header.
	{ID: "I2", Name: "relay-header-allowed-port", Probe: relayProbe, Host: relayCanary("tcp4", hostAddr+":"+forwardPort, "tcp"), Want: forwarded},
	{ID: "I2", Name: "relay-header-allowed-port-udp", Probe: relayProbe, Host: relayCanary("udp4", hostAddr+":"+forwardPort, "udp"), Want: forwarded},
	{ID: "I12", Name: "relay-short-header", Probe: relayProbe, Host: relayHeld("short"), Bound: relayBound},
	{ID: "I12", Name: "relay-slow-header", Probe: relayProbe, Host: relayHeld("slow"), Bound: relayBound},
	// A real guest's 127.0.0.1 is its own loopback. The host's loopback services
	// it could reach are those bound to every host address, dialled as the host.
	{ID: "I4", Name: "host-loopback-tcp4", Probe: dialProbe, Host: tcpCanary("tcp4", "0.0.0.0:0", hostAddr)},
	{ID: "I4", Name: "lan-rfc1918-tcp4", Probe: dialProbe, Host: onLoopback("10.255.255.254", tcpCanary("tcp4", "10.255.255.254:0", ""))},
	{ID: "I4", Name: "link-local-tcp4", Probe: dialProbe, Host: onLoopback("169.254.1.1", tcpCanary("tcp4", "169.254.1.1:0", ""))},
	{ID: "I4", Name: "metadata-tcp4", Probe: dialProbe, Host: onLoopback("169.254.169.254", tcpCanary("tcp4", "169.254.169.254:0", ""))},
	// The relay header names the host's own loopback and the metadata address.
	{ID: "I4", Name: "relay-header-host-loopback", Probe: relayProbe, Host: relayCanary("tcp4", "127.0.0.1:0", "tcp")},
	{ID: "I4", Name: "relay-header-metadata", Probe: relayProbe, Host: onLoopback("169.254.169.254", relayCanary("tcp4", "169.254.169.254:0", "tcp"))},
	// Rebinding: the guest connects to an allowed name, by its forward port or
	// by SNI at 443, and the judge, as the host's resolver, answers it with the
	// host's loopback, a LAN address, the metadata address, loopback as an
	// IPv4-mapped IPv6 address, the unspecified address, or a CNAME to a denied
	// name that is loopback. The canary at the answer must see nothing.
	{ID: "I4", Name: "rebind-loopback-forward", Probe: rebindProbe, Host: rebindJudge(rebind{a: []string{"127.0.0.1"}, canary: "127.0.0.1"}), Want: rebinding},
	{ID: "I4", Name: "rebind-loopback-sni", Probe: rebindProbe, Host: rebindJudge(rebind{a: []string{"127.0.0.1"}, canary: "127.0.0.1", sni: true}), Want: rebindingSNI},
	{ID: "I4", Name: "rebind-lan-forward", Probe: rebindProbe, Host: onLoopback("10.255.255.254", rebindJudge(rebind{a: []string{"10.255.255.254"}, canary: "10.255.255.254"})), Want: rebinding},
	{ID: "I4", Name: "rebind-metadata-forward", Probe: rebindProbe, Host: onLoopback("169.254.169.254", rebindJudge(rebind{a: []string{"169.254.169.254"}, canary: "169.254.169.254"})), Want: rebinding},
	{ID: "I4", Name: "rebind-metadata-sni", Probe: rebindProbe, Host: onLoopback("169.254.169.254", rebindJudge(rebind{a: []string{"169.254.169.254"}, canary: "169.254.169.254", sni: true})), Want: rebindingSNI},
	{ID: "I4", Name: "rebind-unspecified-forward", Probe: rebindProbe, Host: rebindJudge(rebind{a: []string{"0.0.0.0"}, canary: "0.0.0.0"}), Want: rebinding},
	{ID: "I4", Name: "rebind-cname-denied-forward", Probe: rebindProbe, Host: rebindJudge(rebind{cname: deniedName, a: []string{"127.0.0.1"}, canary: "127.0.0.1"}), Want: rebindingCNAME},
	// Last: its A answer is empty, which a Mac's resolver holds for 100 s (U-701).
	{ID: "I4", Name: "rebind-mapped-loopback-forward", Probe: rebindProbe, Host: rebindJudge(rebind{aaaa: []string{"::ffff:127.0.0.1"}, canary: "127.0.0.1"}), Want: rebinding},
	// DNS for a name no policy allows, sent past the guest's resolver straight to
	// a host-side capture: as plain DNS, as DoT, as DoH, and as a tunnel.
	{ID: "I3", Name: "direct-resolver-udp4", Probe: dnsUDPProbe, Host: dnsCanary(dnsOverUDP, queried)},
	{ID: "I3", Name: "direct-resolver-tcp4", Probe: dnsTCPProbe, Host: dnsCanary(dnsOverTCP(false), queried)},
	{ID: "I3", Name: "dot-tcp4", Probe: dotProbe, Host: dnsCanary(dnsOverTCP(true), queried)},
	{ID: "I3", Name: "doh-post-tcp4", Probe: dohProbe(http.MethodPost), Host: dnsCanary(dnsOverHTTPS, queried)},
	{ID: "I3", Name: "doh-get-tcp4", Probe: dohProbe(http.MethodGet), Host: dnsCanary(dnsOverHTTPS, queried)},
	{ID: "I3", Name: "tunnel-txt-udp4", Probe: tunnelProbe, Host: dnsCanary(dnsOverUDP, tunnelled)},
	// The guest's configured resolver must answer the allowed name, in any
	// case and with EDNS0, and refuse every other name (one no policy names, a
	// subdomain, a name that merely ends or starts in it, other types)
	// promptly, with a DNS answer carrying no address. The same at any address
	// on port 53, under a policy allowing nothing, after hostile datagrams
	// (I12) and after a burst (I10).
	{ID: "I3", Name: "resolver-answers-allowed", Probe: lookupProbe, Host: resolverJudge(resolvConf, "plain", allowedLookups), Want: reachable},
	{ID: "I3", Name: "resolver-refuses-others", Probe: lookupProbe, Host: resolverJudge(resolvConf, "plain", deniedLookups), Want: reachable},
	{ID: "I3", Name: "resolver-at-host-address", Probe: lookupProbe, Host: resolverJudge(hostAddr+":53", "plain", bothLookups), Want: reachable},
	{ID: "I3", Name: "resolver-at-lan-address", Probe: lookupProbe, Host: onLoopback("10.255.255.254", resolverJudge("10.255.255.254:53", "plain", bothLookups)), Want: reachable},
	{ID: "I3", Name: "resolver-empty-policy", Probe: lookupProbe, Host: resolverJudge(resolvConf, "plain", nothingLookups)},
	{ID: "I3", Name: "resolver-after-garbage", Probe: lookupProbe, Host: resolverJudge(resolvConf, "garbage", bothLookups), Want: reachable},
	{ID: "I3", Name: "resolver-after-burst", Probe: lookupProbe, Host: resolverJudge(resolvConf, "burst", bothLookups), Want: reachable},
	// A secret lies beside the export on the host. The guest goes for it and its
	// directory by path, link, mount and file handle, and for the host's disks by device node.
	{ID: "I1", Name: "dotdot-traversal", Probe: traversalProbe, Host: outside(nil), Want: exported},
	{ID: "I1", Name: "planted-symlink", Probe: symlinkProbe, Host: outside(plantLinks), Want: exported},
	{ID: "I1", Name: "bind-mount", Probe: mountProbe, Host: outside(nil), Want: exported},
	{ID: "I1", Name: "open-by-handle", Probe: handleProbe, Host: outside(nil), Want: exported},
	{ID: "I1", Name: "device-node", Probe: deviceProbe, Host: deviceJudge, Want: exported},
	{ID: "I1", Name: "link-rename", Probe: moveProbe, Host: outside(nil), Want: exported},
	// The same in mount mode (`--mount`): the export is the user's own tree,
	// served live, so every name the guest utters meets the host's file service
	// (ADR-005); a write inside the export is correct, a byte beside or above it a break.
	{ID: "I1", Name: "mount-dotdot-traversal", Probe: traversalProbe, Host: outside(nil), Want: live},
	{ID: "I1", Name: "mount-planted-symlink", Probe: symlinkProbe, Host: outside(plantLinks), Want: live},
	{ID: "I1", Name: "mount-bind-mount", Probe: mountProbe, Host: outside(nil), Want: live},
	{ID: "I1", Name: "mount-open-by-handle", Probe: handleProbe, Host: outside(nil), Want: live},
	{ID: "I1", Name: "mount-device-node", Probe: deviceProbe, Host: deviceJudge, Want: live},
	{ID: "I1", Name: "mount-link-rename", Probe: moveProbe, Host: outside(nil), Want: live},
	{ID: "I7", Name: "cross-session-residue", Probe: residueProbe, Host: residueJudge, Want: exported},
	// Root changes the provider layer the host installed; the next session must not see it.
	{ID: "I7", Name: "layer-read-only", Probe: layerProbe, Host: layerJudge}, // and B8: a digest mismatch is refused
	// The guest asks for twice its cap; the host, watched from outside, must give no more than the cap.
	{ID: "I10", Name: "fork-flood", Probe: forkProbe, Host: forkJudge, Want: capped},
	{ID: "I10", Name: "memory-flood", Probe: memoryProbe, Host: memoryJudge, Want: capped},
	{ID: "I10", Name: "disk-flood", Probe: diskProbe, Host: diskJudge, Want: capped},
	{ID: "I10", Name: "descriptor-flood", Probe: fileProbe, Host: fileJudge, Want: capped},
	{ID: "I10", Name: "log-flood", Probe: logProbe, Host: logJudge, Want: capped},
	{ID: "I10", Name: "cpu-flood", Probe: cpuProbe, Host: cpuJudge, Want: capped},
	// The same disk flood in mount mode: the export is the host's own tree, served
	// live, so a byte the guest writes under it, or a size it sets without writing, is the host's at once.
	{ID: "I10", Name: "mount-disk-flood", Probe: mountDiskProbe, Host: mountDiskJudge, Want: cappedLive},
	// A secret is bound to one allowed name, both terminated on the host. The
	// guest hunts for the real value in every process, on disk and in memory;
	// sends its credential, alone and as a bearer token, in the bound header to
	// the bound name, which must reach the canary real; replays it at the other
	// name, in another header, in the path and in the query, none of which may
	// reach a canary. Under a binding narrowed to one method and path, only
	// that is swapped. A redirect from the bound host carries it on to the other.
	{ID: "I5", Name: "secret-in-guest", Probe: secretProbe, Host: secretJudge, Want: withSecret},
	{ID: "I5", Name: "placeholder-swapped", Probe: exchangeProbe, Host: twoNames(canaries{}, swapJudge("GET,bound,/check,header", "GET,bound,/bearer,bearer")), Want: withSecret},
	{ID: "I5", Name: "placeholder-replay", Probe: exchangeProbe, Host: twoNames(canaries{}, swapJudge("GET,bound,/check,header", "GET,other,/replay,header")), Want: withSecret},
	{ID: "I5", Name: "placeholder-misplaced", Probe: exchangeProbe, Host: twoNames(canaries{}, swapJudge("GET,bound,/check,header", "GET,other,/replay,header", "GET,bound,/auth,auth", "GET,bound,/path,path", "GET,bound,/query,query")), Want: withSecret},
	{ID: "I5", Name: "placeholder-narrowed", Probe: exchangeProbe, Host: twoNames(canaries{}, swapJudge("POST,bound,/v1/ok,header", "GET,bound,/v1/ok,header", "POST,bound,/v2/no,header", "GET,bound,/check,header")), Want: narrowed},
	{ID: "I5", Name: "redirect-carries-secret", Probe: exchangeProbe, Host: twoNames(canaries{respond: redirectTo}, swapJudge("GET,bound,/check,header", "GET,bound,/start,header")), Want: withSecret},
	// A git token scoped to one repository: a clone's and a push's smart-HTTP
	// requests there carry the real token as git sends it (Basic); the same
	// placeholder on any other path of the host reaches nothing.
	{ID: "I5", Name: "repo-token-swapped", Probe: exchangeProbe, Host: twoNames(canaries{}, swapJudge("GET,bound,/octo/allowed.git/info/refs?service=git-upload-pack,basic", "POST,bound,/octo/allowed.git/git-upload-pack,basic", "POST,bound,/octo/allowed.git/git-receive-pack,basic", "GET,bound,/octo/allowed,basic", "GET,bound,/octo/allowed.git/info/refs?service=git-receive-pack,auth")), Want: scoped},
	{ID: "I5", Name: "repo-token-elsewhere", Probe: exchangeProbe, Host: twoNames(canaries{}, swapJudge("GET,bound,/octo/allowed.git/info/refs?service=git-upload-pack,basic", "GET,bound,/octo/other.git/info/refs?service=git-upload-pack,basic", "POST,bound,/octo/other.git/git-receive-pack,basic", "GET,bound,/other/allowed.git/info/refs,basic", "GET,bound,/octo/allowed-x.git/info/refs,basic", "GET,bound,/octo/allowed.git-x/info/refs,basic", "GET,bound,/Octo/Allowed.git/info/refs,basic", "GET,bound,/octo/allowed.git/../other.git/info/refs,basic", "GET,bound,/octo/allowed.git%2F..%2Fother.git/info/refs,basic", "GET,bound,//octo/allowed.git/info/refs,basic", "GET,bound,/octo/other.git/git-upload-pack,auth", "GET,other,/octo/allowed.git/info/refs,basic")), Want: scoped},
	// A secret whose source is a sign-in flow: the token endpoint on one allowed
	// name issues an access and a refresh token, the access one bound to the
	// API on the other (signin.go). The guest signs in; uses the access token
	// at the API, which must see the real one; refreshes as a form and as JSON,
	// which must reach the endpoint real, and uses the new token; hunts for the
	// real tokens as secret-in-guest does; replays what it holds in the wrong
	// header, as a bearer, in a query and at the wrong host or path; and meets a
	// token response split inside a token, one gzipped, and a 4xx echoing the refresh token.
	{ID: "I5", Name: "signin-exchange", Probe: signinProbe, Host: signedIn("", "signin", "api"), Want: signedInWant},
	{ID: "I5", Name: "signin-refresh", Probe: signinProbe, Host: signedIn("", "signin", "api", "refresh", "api"), Want: signedInWant},
	{ID: "I5", Name: "signin-refresh-json", Probe: signinProbe, Host: signedIn("", "signin", "refresh-json", "api"), Want: signedInWant},
	{ID: "I5", Name: "signin-scan", Probe: signinProbe, Host: signedIn("", "signin", "api", "refresh", "scan"), Want: signedInWant},
	{ID: "I5", Name: "signin-replay", Probe: signinProbe, Host: signedIn("", "signin", "replay", "api"), Want: signedInWant},
	{ID: "I5", Name: "signin-chunked", Probe: signinProbe, Host: signedIn("chunked", "signin", "api", "refresh", "api"), Want: signedInWant},
	{ID: "I5", Name: "signin-gzip", Probe: signinProbe, Host: signedIn("gzip", "signin", "api"), Want: signedInWant},
	{ID: "I5", Name: "signin-error-echo", Probe: signinProbe, Host: signedIn("", "signin", "refresh-bad", "api"), Want: signedInWant},
	// Two allowed names, both terminated on the host. On a connection whose TLS
	// names one, the request names the other, in the Host header, in :authority,
	// or hidden from the SNI by ECH: neither canary may see a request for the
	// other. A plain client in the guest must meet the host's own leaf, trusted
	// through the environment the product set, never the canary's: terminated,
	// not spliced. A canary presenting a leaf for the other name gets no request.
	{ID: "I6", Name: "sni-host-mismatch-h1", Probe: mismatchProbe(false), Host: twoNames(canaries{}, strictJudge), Want: terminating},
	{ID: "I6", Name: "sni-authority-mismatch-h2", Probe: mismatchProbe(true), Host: twoNames(canaries{}, strictJudge), Want: terminating},
	{ID: "I6", Name: "ech-hidden-sni", Probe: echProbe, Host: twoNames(canaries{ech: true}, strictJudge), Want: terminating},
	{ID: "I6", Name: "terminated-session-leaf", Probe: terminatedProbe, Host: twoNames(canaries{}, terminationJudge), Want: terminating},
	{ID: "I6", Name: "upstream-leaf-mismatch", Probe: upstreamProbe, Host: twoNames(canaries{misleaf: true}, upstreamJudge), Want: terminating},
	// The repository the guest hands back is hostile: its hooks, config,
	// attributes and submodule URL aim at the host, and its tree names paths through
	// "..", through a symlink an earlier pull brought, twice in different case, and under ".git".
	{ID: "I8", Name: "pull-runs-hook", Probe: repoProbe, Host: obeyed("hooks"), Want: exported},
	{ID: "I8", Name: "pull-obeys-git-config", Probe: repoProbe, Host: obeyed("config"), Want: exported},
	{ID: "I8", Name: "pull-fetches-submodule", Probe: repoProbe, Host: fetched, Want: exported},
	{ID: "I8", Name: "pull-dotdot-path", Probe: repoProbe, Host: obeyed("dotdot"), Want: exported},
	{ID: "I8", Name: "pull-through-symlink", Probe: repoProbe, Host: obeyed("link", "fill"), Want: exported},
	{ID: "I8", Name: "pull-case-collision", Probe: repoProbe, Host: collided, Want: exported},
	{ID: "I8", Name: "pull-writes-dotgit", Probe: repoProbe, Host: planted, Want: exported},
	// A workcell.toml in the repository tries to widen the policy: the allowlist,
	// by another spelling of a name or through a symlink out of the repository;
	// the secret's binding, to another host, header or source, or free of its
	// method and path; the workspace mode; the caps. The guest replays its
	// credential at the name only the repository allows or binds, and must see
	// nothing. One file narrows the allowlist, which must hold. One is a pipe.
	{ID: "I13", Name: "repo-policy-widens-allowlist", Probe: exchangeProbe, Host: twoNames(canaries{}, swapJudge("GET,bound,/check,header", "GET,other,/replay,header")), Want: widened},
	{ID: "I13", Name: "repo-policy-respells-name", Probe: exchangeProbe, Host: twoNames(canaries{}, swapJudge("GET,bound,/check,header", "GET,other,/replay,header", "GET,other,/plain,none")), Want: respelled},
	{ID: "I13", Name: "repo-policy-through-symlink", Probe: exchangeProbe, Host: twoNames(canaries{}, swapJudge("GET,bound,/check,header", "GET,other,/plain,none")), Want: linked},
	{ID: "I13", Name: "repo-policy-narrows-allowlist", Probe: exchangeProbe, Host: twoNames(canaries{}, swapJudge("GET,bound,/check,header", "GET,other,/plain,none")), Want: narrowing},
	{ID: "I13", Name: "repo-policy-rebinds-secret", Probe: exchangeProbe, Host: twoNames(canaries{}, swapJudge("GET,bound,/check,header", "GET,other,/replay,header")), Want: rebound},
	{ID: "I13", Name: "repo-policy-lifts-secret-binding", Probe: exchangeProbe, Host: twoNames(canaries{}, swapJudge("POST,bound,/v1/ok,header", "GET,bound,/check,header", "POST,bound,/v2/no,header")), Want: lifted},
	{ID: "I13", Name: "repo-policy-rewires-secret", Probe: exchangeProbe, Host: twoNames(canaries{}, swapJudge("GET,bound,/check,header", "GET,bound,/auth,auth")), Want: rewired},
	{ID: "I13", Name: "repo-policy-mounts-workspace", Probe: liveProbe, Host: liveJudge, Want: mounted},
	{ID: "I13", Name: "repo-policy-is-a-pipe", Probe: liveProbe, Host: liveJudge, Want: piped},
	{ID: "I13", Name: "repo-policy-lifts-memory-cap", Probe: memoryProbe, Host: memoryJudge, Want: uncapped},
	// The guest, told where the host keeps the session's record, plants a
	// record, sends the record's path to /dev/null, or empties it; and a user with
	// the file drops, alters, cuts, appends or reorders records after the fact, which verify must notice.
	{ID: "I9", Name: "audit-forge-record", Probe: auditProbe, Host: auditJudge("forge"), Want: exported},
	{ID: "I9", Name: "audit-suppress-record", Probe: auditProbe, Host: auditJudge("suppress")},
	{ID: "I9", Name: "audit-truncate-record", Probe: auditProbe, Host: auditJudge("truncate")},
	{ID: "I9", Name: "verify-dropped-record", Probe: auditProbe, Host: offlineJudge("drop")},
	{ID: "I9", Name: "verify-altered-byte", Probe: auditProbe, Host: offlineJudge("alter")},
	{ID: "I9", Name: "verify-truncated-record", Probe: auditProbe, Host: offlineJudge("truncate")},
	{ID: "I9", Name: "verify-appended-record", Probe: auditProbe, Host: offlineJudge("append")},
	{ID: "I9", Name: "verify-swapped-records", Probe: auditProbe, Host: offlineJudge("swap")},
	// The guest connects to an allowed name and to a denied one; the records the
	// run adds must name both attempts, let through and refused. The names
	// reach the guest in hex, so its own words cannot put them in the record.
	{ID: "I9", Name: "audit-records-connection", Probe: connectProbe, Host: recordedJudge, Want: servable},
	// Each host helper is killed with SIGKILL while the guest holds a connection
	// it was served through, and the proxy once more while the guest is still
	// booting. After, nothing of the session may run, the held connection must
	// close, and no canary and no resolver may hear from the guest. In the
	// product the helpers are one process with the supervisor (A9); the rows stand for the day they are not.
	{ID: "I11", Name: "proxy-killed", Probe: holdProbe, Host: helperKilled("proxy", false), Want: servable},
	{ID: "I11", Name: "resolver-killed", Probe: holdProbe, Host: helperKilled("resolver", false), Want: servable},
	{ID: "I11", Name: "broker-killed", Probe: holdProbe, Host: helperKilled("broker", false), Want: servable},
	{ID: "I11", Name: "proxy-killed-at-start", Probe: holdProbe, Host: helperKilled("proxy", true), Want: servable},
	// Root in the guest writes on the init's own channel connection: frames
	// no decoder can take, a forged Exit under a version the host never
	// issued, an error text made of terminal escapes, a 4 GiB header then
	// silence, one byte a second; and a storm of fresh connections each
	// carrying a forged Exit. The host must end each run in time, without a
	// crash, with a clean stderr and the truthful status, and run again after.
	{ID: "I12", Name: "channel-malformed-frames", Probe: channelProbe, Host: channelJudge("exit-empty", "ack-short", "version-2", "unknown-type"), Bound: channelBound},
	{ID: "I12", Name: "channel-forged-exit-text", Probe: channelProbe, Host: channelJudge("exit-text"), Bound: channelBound},
	{ID: "I12", Name: "channel-oversized-frame", Probe: channelProbe, Host: channelJudge("giant-header"), Bound: channelBound},
	{ID: "I12", Name: "channel-slow-drip", Probe: channelProbe, Host: channelJudge("slow-drip"), Bound: channelBound},
	{ID: "I12", Name: "channel-connect-storm", Probe: channelProbe, Host: channelJudge("storm"), Bound: channelBound},
	{ID: "I12", Name: "channel-connect-flood", Probe: channelProbe, Host: floodJudge, Bound: channelBound},
	{ID: "I12", Name: "channel-cut-mid-frame", Probe: channelProbe, Host: channelJudge("half-close", "full-shutdown"), Bound: channelBound},
	{ID: "I12", Name: "channel-frames-after-exit", Probe: channelProbe, Host: channelJudge("after-exit"), Bound: channelBound},
	// The update client on the host, after one honest install from a channel
	// the judge signs and serves, meets a manifest signed by another key or
	// with a corrupted signature, past its expiry, below the last serial or
	// a day ahead, and an artifact whose bytes do not match, stop short,
	// come by a redirect, or come without TLS. None may install, and a
	// valid successor must.
	{ID: "I14", Name: "update-wrong-key", Probe: idleProbe, Host: updateJudge("wrong-key")},
	{ID: "I14", Name: "update-corrupt-signature", Probe: idleProbe, Host: updateJudge("corrupt-signature")},
	{ID: "I14", Name: "update-expired-manifest", Probe: idleProbe, Host: updateJudge("expired")},
	{ID: "I14", Name: "update-lower-serial", Probe: idleProbe, Host: updateJudge("lower-serial")},
	{ID: "I14", Name: "update-serial-ahead", Probe: idleProbe, Host: updateJudge("serial-ahead")},
	{ID: "I14", Name: "update-digest-mismatch", Probe: idleProbe, Host: updateJudge("digest-mismatch")},
	{ID: "I14", Name: "update-truncated-download", Probe: idleProbe, Host: updateJudge("truncated")},
	{ID: "I14", Name: "update-redirected-url", Probe: idleProbe, Host: updateJudge("redirected")},
	{ID: "I14", Name: "update-plain-http-url", Probe: idleProbe, Host: updateJudge("plain-http")},
	// The installer's second entry: the channel check a session start makes
	// by itself, and the install the next start makes from what it kept. A
	// manifest under another key or past its expiry must install nothing;
	// a valid one installs exactly the digest it pins, after one check a day.
	{ID: "I14", Name: "update-daily-wrong-key", Probe: idleProbe, Host: dailyJudge("wrong-key")},
	{ID: "I14", Name: "update-daily-expired", Probe: idleProbe, Host: dailyJudge("expired")},
	{ID: "I14", Name: "update-daily-once", Probe: idleProbe, Host: dailyJudge("once")},
	// The product's own start benchmark, run on the host: twenty warm boots,
	// and the median must be under the hosted budget.
	{ID: "P1", Name: "warm-start", Probe: idleProbe, Host: benchJudge, Bound: benchBound},
}, pinSmoke()...) // and B6, a smoke test of each guest pin that changed (smoke.go)

// hostAddr, in a canary address, stands for the host's own first non-loopback
// IPv4 address: what a real guest sees as the host.
const hostAddr = "host"

// forwardPort is the one port the policy forwarded opens, as a forward entry
// for one name: above the privileged range and below the ephemeral one, so
// that a canary can bind it on the host without privilege. A guest program
// that dials any address at it meets the product's listener; the product
// serves the port for the name alone, which it resolves on the host, and
// that name resolves nowhere in this suite (a name that reaches the test
// host is the host resolver's, U-304 and U-305).
const forwardPort = "8443"

var forwarded = Want{Allow: []string{"allowed.escape.test:" + forwardPort}}

// dialProbe connects to args[0] and sends the token args[1] on one line.
func dialProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want address and token"}
	}
	c, err := net.DialTimeout("tcp", args[0], 3*time.Second)
	if err != nil {
		return dialFailed(err)
	}
	defer c.Close()
	if _, err := fmt.Fprintln(c, args[1]); err != nil {
		return Result{Status: "connected-write-failed", Detail: err.Error()}
	}
	// With every address local to the guest (ADR-003) a completed connect
	// proves nothing by itself; only the canary's catch does.
	return Result{Status: "connected", Detail: "to " + args[0]}
}

// udpProbe sends the token args[1] as a datagram line to args[0].
func udpProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want address and token"}
	}
	return sendUDP(args[0], []byte(args[1]+"\n"))
}

// quicProbe sends a QUIC v1 Initial packet to args[0] whose destination
// connection ID is the token args[1].
func quicProbe(args []string) Result {
	if len(args) != 2 {
		return Result{Status: "error", Detail: "want address and token"}
	}
	dcid, err := hex.DecodeString(args[1])
	if err != nil || len(dcid) > maxCID {
		return Result{Status: "error", Detail: "token is not a connection ID"}
	}
	return sendUDP(args[0], quicInitial(dcid))
}

func sendUDP(addr string, b []byte) Result {
	c, err := net.DialTimeout("udp", addr, 3*time.Second)
	if err != nil {
		return Result{Status: "unreachable", Detail: err.Error()}
	}
	defer c.Close()
	if _, err := c.Write(b); err != nil {
		return Result{Status: "send-failed", Detail: err.Error()}
	}
	return Result{Status: "sent", Detail: fmt.Sprintf("%d bytes to %s", len(b), addr)}
}

func newToken() string {
	token := make([]byte, 16)
	rand.Read(token)
	return hex.EncodeToString(token)
}

// resolve replaces hostAddr in a canary address with the host's own first
// non-loopback IPv4 address.
func resolve(addr string) (string, error) {
	if !strings.Contains(addr, hostAddr) {
		return addr, nil
	}
	host, err := sandbox.HostAddr()
	if err != nil {
		return "", err
	}
	return strings.ReplaceAll(addr, hostAddr, host), nil
}

// trap is a canary: a listener on the host that keeps what every connection
// (its first line) or every datagram delivered. What arrived is the proof of
// reach; the guest's word is not.
type trap struct {
	ln   net.Listener
	pc   net.PacketConn
	mu   sync.Mutex
	got  [][]byte
	wg   sync.WaitGroup
	done bool
}

// listenTrap starts a trap on network ("tcp4", "tcp6" or "udp4") at addr.
// A port below 1024 needs root; helper, when set, is the payload, which
// binds it through sudo (privileged) when the suite is not root itself.
func listenTrap(network, addr string, helper ...string) (*trap, error) {
	t := &trap{}
	var err error
	if strings.HasPrefix(network, "udp") {
		t.pc, err = net.ListenPacket(network, addr)
	} else {
		t.ln, err = net.Listen(network, addr)
	}
	if errors.Is(err, syscall.EACCES) && len(helper) == 1 {
		t.ln, t.pc, err = privileged(network, addr, helper[0])
	}
	if err != nil {
		return nil, fmt.Errorf("canary listener: %w", err)
	}
	t.wg.Go(t.serve)
	return t, nil
}

func (t *trap) serve() {
	if t.pc != nil {
		buf := make([]byte, 2048)
		for {
			n, _, err := t.pc.ReadFrom(buf)
			if err != nil {
				return
			}
			t.keep(bytes.Clone(buf[:n]))
		}
	}
	for {
		c, err := t.ln.Accept()
		if err != nil {
			return
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		line, _ := bufio.NewReaderSize(c, 128).ReadString('\n')
		c.Close()
		t.keep([]byte(line))
	}
}

func (t *trap) keep(b []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.got = append(t.got, b)
}

// addr is where the trap listens.
func (t *trap) addr() string {
	if t.pc != nil {
		return t.pc.LocalAddr().String()
	}
	return t.ln.Addr().String()
}

// stop closes the trap, after a moment for a datagram still in flight on
// loopback or a connection the kernel queued that serve has not accepted yet
// (closing the listener would drop it uncounted), and returns everything that arrived.
func (t *trap) stop() [][]byte {
	t.mu.Lock()
	done := t.done
	t.done = true
	t.mu.Unlock()
	if !done {
		time.Sleep(200 * time.Millisecond)
		if t.pc != nil {
			t.pc.Close()
		} else {
			t.ln.Close()
		}
	}
	t.wg.Wait()
	return t.got
}

// verdict judges a trap's catch. A connection or datagram carrying the token
// is proof that the guest reached the canary; on a stream canary so is any
// connection at all; a stray datagram from elsewhere on the host is not.
func verdict(got [][]byte, carries func([]byte, string) bool, want, target string, stream bool, say string) (bool, string) {
	hits := 0
	for _, b := range got {
		if carries(b, want) {
			hits++
		}
	}
	switch {
	case hits > 0:
		return false, fmt.Sprintf("the guest reached the canary at %s and delivered its token, %d times (%s)", target, hits, say)
	case stream && len(got) > 0:
		return false, fmt.Sprintf("the guest connected to the canary at %s, %d times (%s)", target, len(got), say)
	}
	return true, fmt.Sprintf("nothing from the guest reached the canary at %s (%d others; %s)", target, len(got), say)
}

// says is a guest's result as a judge quotes it.
func says(r Result) string { return fmt.Sprintf("guest says %s: %s", r.Status, r.Detail) }

// tcpCanary listens on addr and has the guest dial it, as dialHost when that is
// set (another address or spelling that reaches the same listener), else as
// the listener's own address. udpCanary listens for datagrams at addr and has
// the guest send the token there. The invariant holds only if nothing
// arrives: a connection or a datagram is proof of reach; the guest's word is not.
func tcpCanary(network, addr, dialHost string) Judge {
	return trapJudge(network, addr, dialHost, lineToken, true)
}

func udpCanary(addr string, carries func(b []byte, token string) bool) Judge {
	return trapJudge("udp4", addr, "", carries, false)
}

func trapJudge(network, addr, dialHost string, carries func([]byte, string) bool, stream bool) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		addr, err := resolve(addr)
		if err == nil {
			dialHost, err = resolve(dialHost)
		}
		if err != nil {
			return false, "", err
		}
		t, err := listenTrap(network, addr)
		if err != nil {
			return false, "", err
		}
		defer t.stop()
		target := t.addr()
		if dialHost != "" {
			_, port, _ := net.SplitHostPort(target)
			target = net.JoinHostPort(dialHost, port)
		}
		want := newToken()
		r, err := s.Run(target, want)
		got := t.stop()
		if err != nil {
			return false, "", err
		}
		pass, detail := verdict(got, carries, want, target, stream, says(r))
		return pass, detail, nil
	}
}

// lineToken and quicToken say whether a datagram carries the token.
func lineToken(b []byte, token string) bool { return string(b) == token+"\n" }
func quicToken(b []byte, token string) bool {
	dcid, ok := quicDCID(b)
	return ok && hex.EncodeToString(dcid) == token
}

// icmpJudge has the guest ping the host's own address with the token as the
// echo payload. The invariant holds only if no reply carries the token back.
func icmpJudge(ctx context.Context, s Session) (bool, string, error) {
	host, err := resolve(hostAddr)
	if err != nil {
		return false, "", err
	}
	r, err := s.Run(host, newToken())
	if err != nil {
		return false, "", err
	}
	if r.Status == "echo-reply" {
		return false, "the host answered the guest's ICMP echo to " + host + " with its token: " + r.Detail, nil
	}
	return true, fmt.Sprintf("guest says %s: %s", r.Status, r.Detail), nil
}

// onLoopback runs judge while ip, which the host does not otherwise own, is an
// address of the host's loopback interface. A guest that reaches it has reached
// the host; no packet to it can leave the host.
func onLoopback(ip string, judge Judge) Judge {
	return func(ctx context.Context, s Session) (bool, string, error) {
		remove, err := loopbackAddr(net.ParseIP(ip))
		if err != nil {
			return false, "", err
		}
		defer remove()
		return judge(ctx, s)
	}
}
