# Blocked

Units the loop has marked `[!]`, because they failed three times or need something only the maintainer can give.
One entry per unit: what is needed, why, and what would unblock it. An entry that says only
`needs the maintainer, see the run's transcript` stands for anything that cannot be said in public, or that only the
maintainer has: a credential, a purchase, a legal reading. The loop has halted with the reason `needs-you`. The detail
is in the transcript of the run that logged it, never here.

When it is resolved, delete the entry, and in `PLAN.md` set the unit back to `[ ]` and its `tries` back to 0. Rewrite or
split the unit if it was too big or too vague. Land both files with `land.sh`.



## S-1017: the third sweep confirmed findings at medium and above (SPEC S8)

Needed: the maintainer's decision on a design question. Nothing here is private, and no credential, purchase or
legal reading is asked for, so this is not `needs-you`.

Why: sweep 3, the last that S8 allows, confirmed two highs (C76, C77) and sixteen mediums (C65 to C69, C71 to C75,
C78, C80 to C82, C85, C86). All 23 findings of the sweep are fixed, their tests are in the suite, and every `S-F`
unit is `[x]`. But the accept line asks for a sweep with nothing confirmed at medium or above, and S8 says that a
third sweep which still confirms one is a design problem and not another patch. So, as the unit line says, the
loop marks S-1017 `[!]` and calls no fourth sweep. R-5, S-1018 and H-1019 wait behind it. The section
`S-1017: sweep verdict, sweep 3` of `FINDINGS.md` holds the table, the class of each medium and the open rows.

Where the mediums gather: six are residues of the secret-source check of loadPolicy in cmd/workcell/policy.go
(C72, C75, C78, C80, C81, C82, after C54 and C58 of sweep 2), and four are of the method-and-path rule of a
`[[secret]]`, admits in internal/proxy/terminate.go (C68, C71, C73, C74). Both judge words as text, and each fix
left rows that a later audit confirmed. `PARKED.md` still holds eight rows of the first check with a reproduction
and no verifier's ruling, under the lines that begin `S-F64 redteam, reviewer and builder notes`,
`S-F65 redteam and reviewer notes` and `S-F66 redteam notes`, and two reasoned residues of the directory checks
under `S-F69 not closed` and `S-F70 not closed`. R-4 left them there for this decision.

What would unblock it: the maintainer decides whether those checks get another design, which rows are accepted
as residual risk, and whether any surface is audited again. Setting S-1017 alone back to `[ ]` repeats this
verdict, because the sweep count stays at 3 and the accept line is still not met. So the decision lands as a
signed change: new or rewritten units, the audit units to run again set back to `[ ]`, and this unit's line or
S8 itself saying what a further sweep must show.
