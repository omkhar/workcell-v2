# Blocked

Units the loop has marked `[!]`, because they failed three times or need something only the maintainer can give.
One entry per unit: what is needed, why, and what would unblock it. An entry that says only
`needs the maintainer, see the run's transcript` stands for anything that cannot be said in public, or that only the
maintainer has: a credential, a purchase, a legal reading. The loop has halted with the reason `needs-you`. The detail
is in the transcript of the run that logged it, never here.

When it is resolved, delete the entry, and in `PLAN.md` set the unit back to `[ ]` and its `tries` back to 0. Rewrite or
split the unit if it was too big or too vague. Land both files with `land.sh`.



- S-1008: blocked by the SPEC section 7 test budget, not by the audit. The audit is complete and recorded in FINDINGS.md
  (section S-1008: four confirmed findings, C17 and C18 high, C19 medium, C20 low, with fix units S-F10 to S-F13 added to
  PLAN.md below it). S4 says each reproducing test waits under escape/_pending/S-F<n>/ until its fix unit moves it into place,
  and those four tests are 308 lines after condensing, while the gate's test budget (1.5 x product + 5000 = 27491 at product
  14994) has 44 lines of room. The redteam searched escape/ for unreferenced and duplicated code with a symbol lister and the
  go/types checker on linux and darwin and found 20 lines, so the pending tests leave the gate 244 lines over; everything
  else under escape/ is a T2-proven row, probe, judge or adapter, and deleting one would weaken the suite. Needed: a
  maintainer edit to the test budget in SPEC section 7, by about 400 lines so that the four fix units can also move their
  tests into internal/fileserve/ and cmd/workcell/ (net zero against _pending, but each fix unit may need a line or two), or
  a maintainer deletion of test code. The four tests and the audit's work are on branch claude/S-1008-20261115T020531Z of
  the closed claim pull request 211 (escape/_pending/S-F10 to S-F13 at its head). To unblock: raise the budget, then either
  cherry-pick the pending tests from that branch and set S-1008 to [x] (the record is already in FINDINGS.md), or set it back
  to [ ] and let the next run redo the audit; the S-F units depend on S-1008 and wait either way.
