# ADR-006: judge a structure the host itself resolves or sends

status: proposed

## Context

Sweep 3 stopped under S8 on two checks that judge text another program reads again, and each fix left rows a later audit confirmed (FINDINGS.md, S-1017 sweep 3). One: the
word loop of loadPolicy (cmd/workcell/policy.go 32-35 and 80-100, 25 lines) splits a `file:` or `cmd:` source into words, cuts each at slashes and at every separator byte,
reads it from `/` as well, refuses twelve shell characters and judges each piece against the working directory (C54, C58, C72, C75, C78, C80, C81, C82). The host itself opens
one path per row: Resolve (internal/secret/source.go) opens the `file:` path, or execs argv[0] of a `cmd:` source from `/` with no shell; every later word is argv for that
program, whose reading the host cannot know. Two: admits (internal/proxy/terminate.go 110-137, with fold and opaque in signin.go 66-75) guesses how an upstream framework
re-reads a request: three readings of the path (C10, C33), six override names as headers and query parameters under a CGI and PHP name fold (C68, C74), and any body a
framework takes a method from (C71, C73). The host itself sends one structure: httputil.ReverseProxy writes r.Out, whose request line is the parsed Method and
URL.RequestURI(), that is EscapedPath() ("u.RawPath when it is a valid escaping of u.Path", else Go's own escaping of u.Path) and the query. Attacker (SPEC 2): guest root
and hostile model output; every row of check one also needs the operator's own row and layout, every row of check two an upstream behind such a framework (S6, medium).
Product is at 15000 of 15000, test at 28497 of 28500, and there is no prototype (U-905a): S-F71 and S-F72 carry the proof. I5, I6, I13, A1, A4, A11, T3 and T5 apply.

## Check one: the secret source

| | (a) judge the one path the host opens or runs | (b) outcome: refuse an export or mount that holds the resolved value | (c) no check; the duty in docs/policy.md | today |
|---|---|---|---|---|
| Judged | the `file:` path and argv[0] of a `cmd:` as the kernel walks them: absolute, every prefix resolved (leadsInto, data.go) against cwd and the data directory; the scheme as Resolve's switch spells it; a `file:` is one regular file with one name (os.Stat, Nlink) | the value bytes, read at start by Resolve, against every file the export walk reads (workspace.go) and a new walk of cwd under --mount | nothing | every word, cut at slashes and separators, from `/` too |
| Text read again | none: a word after the program is the program's own and is not read | the bytes: a `.git` object holds the key zlib-compressed and a `.env` may hold it base64, so `git show` reads it again; a script under cwd that holds no key bytes is still run as the operator after the guest rewrote it | none | all of it: eight rows parked after six fixes |
| Lines; cost | about 16 for 25, net -9; one Stat per `file:` row | about +20 (resolve at start, a value list through Export, a walk under --mount); a keychain prompt or a two-minute program at every start (P1); "read on each use, never at start" becomes false | -25 | 0 |
| Closes | C54's `file:` and program arms, C58, C82, the three rows of PARKED 225 | C54's `file:` arm and C72, C75, C78, C80, C81 where the bytes lie plain | nothing | what it closes today |

Decision: (a). loadPolicy keeps one loop over p.Secret, the user's rows whatever workcell.toml kept (I13, C58). The scheme must be exactly file, cmd, secret-service, keychain
or signin, as Resolve's switch has them. The `file:` path, or the first field of a `cmd:` source as strings.Fields splits it for Resolve, must be absolute and must neither lie
in nor lead into the working directory or the data directory: leadsInto walks every prefix resolved, so `cmd:<cwd>/tool`, a link to /bin/sh, is refused at the prefix `<cwd>`,
as C54's link arms ask. A `file:` path must name, at load, a regular file with one name (os.Stat; Nlink > 1 is refused as holds() refuses it for config.toml; a program is not
held to one name, since a store such as Nix hard-links binaries). One error with C54's words ("lies inside the directory"), before any session directory exists. sep, the
word loop, the separator grammar and the twelve characters go; docs/policy.md 124-129 become two sentences: the `file:` path and the `cmd:` program are judged; what a
program reads through its arguments is yours, so name nothing under the directory in them, since under --mount the guest can rewrite whatever they name. Newly refused:
a `file:` that is absent, not regular or hard-linked at start (today a dead row, or served); a scheme not spelled as above (today dead); a source in or leading into the data
directory. Newly admitted: every word after the program (the rows of C72, C75, C78, C80 and C81, the twelve characters, an interpreter outside running a script inside).
Lines: about -9 (about 16, the syscall import included, for 25). Reversal: one hunk and six doc lines return from git and need 9 lines of budget: low.

## Check two: the method-and-path rule

| | (d) one canonical path, judged as sent; no `method` | (e) judged as sent, `method` kept | (f) refuse or strip every known override, which is today's rule |
|---|---|---|---|
| Path | admitted under a `path` or `repos` rule only when EscapedPath() equals Go's own escaping of the decoded path, is path.Clean of itself but for one trailing slash, and holds no `;` or backslash: one reading, and the bytes Request.Write sends | as (d) | three readings (fold, opaque) |
| Method | the rule names none, so nothing a header, a parameter or a body carries can move it; `method` is refused at load as an unknown key | sent as parsed, but a framework takes it from a form, a JSON body or a mangled query name, so the body rule of C71 and C73 stays and the key suits body-less requests alone, as docs/policy.md already says | six names and the bodies |
| Text kept | two path-override header names (X-Original-URL, X-Rewrite-URL) under RFC 3875's one fold (cgiName): a header is the only carrier of a second path and the fold is one documented rule, so the list is two names where the method carriers were open-ended; EqualFold on the sign-in path, an over-claim that is read whole | the six names, the fold, the body types | the same and PHP's query fold |
| Lines | about -20: methodPattern, Method, the method checks, readable, folded, fold, opaque and the scope switch go (terminate.go -10, signin.go -7, explain.go -3); canonical is 5 | about -8 | 0 |

Decision: (d). admits: an unnarrowed rule swaps on any request; a narrowed one only when canonical(req.URL) holds, no header folds to x_original_url or x_rewrite_url, and the
path as sent is under r.Path (or sent+"/" is r.Path) or within a repository, and nothing else: no fold, no body, no query. A sign-in host takes canonical paths only, folded
into serveTerminated's target_refused check (0 lines), and tokenEndpoint claims the path by EqualFold alone, kept because an over-claim is read whole and rewritten (I5)
and tokenResponse still refuses a token-shaped answer the match did not claim. methodPattern, Method, the method checks of NewTerminateRule, readable, folded, fold,
opaque, params, sep and the scope switch go, with the `mime` import; `path` comes. Newly refused: a `[[secret]]` row with `method` (at load, naming the line); under a
narrowed rule a placeholder on a non-canonical path (today `/v1/a%2Fb/c` is served); on a sign-in host any non-canonical path (400). Newly admitted: under a `path` rule,
every method and every body. The suite's narrowed row (escape/suite/secrets.go 42) narrows by path alone; explain loses "POST only". Lines: about -20. Reversal: `method` is
a field, a pattern and the body rule, about 30 lines, and operators who dropped the key add it back, so medium-low; the canonical judge is one function and fold returns from git.

## The findings and the parked rows

| Row | Ruling |
|---|---|
| C54 | closed for `file:` and for a program in, or linked from, the directory (the first prefix inside it refuses the row); accepted for its two `/bin/sh <script in the directory>` arms, which go: the script is argv, the operator named it and shares the tree, and docs/policy.md states the duty |
| C58 | closed: the loop walks p.Secret, the user's rows, whatever workcell.toml kept |
| C82 | closed: a `file:` path must be absolute and a regular file at load |
| C72, C75, C78, C80, C81 | accepted: each is a word after the program, read by the program, naming a key the operator placed under the directory; without the row the key is in the export just the same and no check sees it; a rule over such words did not converge (eight rows after six fixes); the tests go and FINDINGS.md records the rows as accepted |
| PARKED 223 and 224: xargs -a, curl file://localhost, env -C, grep -rh, curl %72epo | accepted, as the row above: each is an argument |
| PARKED 225: FILE:, File:, foo: | closed: the scheme is refused at load |
| PARKED 225: file://localhost<path> | closed: filepath.Abs and the kernel read it as /localhost/<path>, no regular file, so the row is refused at load |
| PARKED 225: a hard link outside the directory to the key inside | closed: a `file:` with Nlink > 1 is refused |
| S-F69 residue (244) | accepted: `l/../x` inside a link target misjudges only a link the operator made outside the directory, since a prefix that enters the directory is refused before any link inside it is followed and the guest links nothing outside its mount (I1); a name made while a session runs is the operator's act; two names of config.toml refused everywhere is a cost, not a risk; a `file:` link to an unmade file is now refused by the Stat and a `cmd:` program so linked is judged by its target, which S-F71 tests; ca and TMPDIR are outside this ADR |
| S-F70 residue (247) | accepted: 26 to 44 ms with SSL_CERT_DIR set is the operator's environment, not a risk; a member added while a session runs is the operator's act; `..` after a link is S-F69's row; a bundle under the config directory is no risk, since C85 refuses a directory that holds it; the two variables unnamed in docs/ is a docs line outside S-F71's sentence |
| C10 | closed: a `;`, a backslash, a dot segment or an encoded separator is not canonical, so the request is refused under a rule and 400 on a sign-in host; S-F72 shows each spelling of c10_test.go gets no token and no secret |
| C33 | closed: `%2F` and `%5C` are not Go's escaping of `/` and `\`, so the path is refused before any router reads it; the served arm `/v1/a%2Fb/c` becomes a refused arm |
| C68 | closed: a method override moves nothing, since the rule names no method; the two path-override headers are refused under the fold kept; the test's method rows become rows served inside the rule |
| C71, C73, C74 | closed: a form field, a JSON field or a mangled query name moves a method the rule does not name; the tests go, and a policy test shows `method` refused at load |

## Consequences

- Product about 14971 of 15000 (-9, -20); SPEC unchanged: section 5's format has no `method`, a key is removed and none added. Tests: c71, c73, c74 and the tests of C72, C75, C78, C80 and C81 go (about 450 lines); S-F71 adds arms for the scheme, the Stat, the Nlink and the link prefix; S-F72 adds the byte-for-byte test its accept names, a `//` and a `%00` row (both stay outside every prefix) and rewrites c33, c68, the suite's narrowed row and the explain rows.
- To prove by running, not settled here: S-F71, that leadsInto refuses `cmd:<cwd>/tool` by its prefix when the target lies outside, and that the Nlink cast builds on darwin as data.go's does; S-F72, that Request.Write sends EscapedPath() unchanged for a canonical path (the local-server test) and that the I6 rows pass with the path-only narrowed row.
- S-F71's accept ("pass, or replaced by arms that hold the same invariant") must be read with this table: an accepted row has no arm, its test is deleted, and FINDINGS.md records the class as fixed for the closed rows and accepted, with the reason above, for the rest. That reading is the maintainer's, at H-1023.
