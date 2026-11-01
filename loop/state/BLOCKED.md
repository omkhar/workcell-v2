# Blocked

Units the loop has marked `[!]`, because they failed three times or need something only the maintainer can give.
One entry per unit: what is needed, why, and what would unblock it. An entry that says only
`needs the maintainer, see the run's transcript` stands for anything that cannot be said in public, or that only the
maintainer has: a credential, a purchase, a legal reading. The loop has halted with the reason `needs-you`. The detail
is in the transcript of the run that logged it, never here.

When it is resolved, delete the entry, and in `PLAN.md` set the unit back to `[ ]` and its `tries` back to 0. Rewrite or
split the unit if it was too big or too vague. Land both files with `land.sh`.

- U-007: needs a maintainer edit to the test-code budget in `loop/SPEC.md` section 7, or product code landed first. The budget is 1.5 x product + 2000 lines and product code is 32 lines, so everything under `escape/` may hold 2048 lines; `main` holds 1860 and U-007 brings 2729. U-008, U-009, U-010 and U-010b have the same problem, because Phase 0 writes evidence before product. The tests were written and shown to fail on control; the LOG entry of 2026-11-01 says how they were built. Unblock: give the test budget a floor that covers Phase 0 (about 5,000 lines under `escape/`), or move the escape units behind the first product units, then set U-007 back to `[ ]`.
