# Blocked

Units the loop has marked `[!]`, because they failed three times or need something only the maintainer can give.
One entry per unit: what is needed, why, and what would unblock it. An entry that says only
`needs the maintainer, see the run's transcript` stands for anything that cannot be said in public, or that only the
maintainer has: a credential, a purchase, a legal reading. The loop has halted with the reason `needs-you`. The detail
is in the transcript of the run that logged it, never here.

When it is resolved, delete the entry, and in `PLAN.md` set the unit back to `[ ]` and its `tries` back to 0. Rewrite or
split the unit if it was too big or too vague. Land both files with `land.sh`.

- U-007: needs a maintainer edit to the test-code budget in `loop/SPEC.md` section 7, or product code landed first. The budget is 1.5 x product + 2000 lines and product code is 32 lines, so everything under `escape/` may hold 2048 lines; `main` holds 1860 and U-007 brings 2729. U-008, U-009, U-010 and U-010b have the same problem, because Phase 0 writes evidence before product. The tests were written and shown to fail on control; the LOG entry of 2026-11-01 says how they were built. Unblock: give the test budget a floor that covers Phase 0 (about 5,000 lines under `escape/`), or move the escape units behind the first product units, then set U-007 back to `[ ]`.
- U-008: the same test-code budget as U-007. On `main` the gate reports 1879 of 2048 test lines (product code 32, limit 1.5 x product + 2000), so 169 lines remain under `escape/`. U-008 needs a canary secret in the harness `Config` and about seven I5 and I6 tests; U-005 and U-006 cost 60 to 95 lines per test. Nothing under `escape/` can go without losing a T2-proven test. No redteam was spent. Unblock as for U-007: raise or floor the test budget, or move the escape units behind the first product units, then set U-008 back to `[ ]`.
- U-009: the same test-code budget as U-007 and U-008. On `main` the gate reports 1879 of 2048 test lines (product code 32, limit 1.5 x product + 2000), so 169 lines remain under `escape/`. U-009 needs about eight I8 and I13 tests (hostile hooks, filters, attributes, `.git/config`, submodule URLs, symlinks, `../` paths, case-collision names, a repo-local policy that widens) at 60 to 95 lines each, plus a return-path hook in the harness. Nothing under `escape/` can go without losing a T2-proven test. No redteam was spent. Unblock as for U-007: raise or floor the test budget, or move the escape units behind the first product units, then set U-009 back to `[ ]`.
