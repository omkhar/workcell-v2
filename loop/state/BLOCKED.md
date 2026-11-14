# Blocked

Units the loop has marked `[!]`, because they failed three times or need something only the maintainer can give.
One entry per unit: what is needed, why, and what would unblock it. An entry that says only
`needs the maintainer, see the run's transcript` stands for anything that cannot be said in public, or that only the
maintainer has: a credential, a purchase, a legal reading. The loop has halted with the reason `needs-you`. The detail
is in the transcript of the run that logged it, never here.

When it is resolved, delete the entry, and in `PLAN.md` set the unit back to `[ ]` and its `tries` back to 0. Rewrite or
split the unit if it was too big or too vague. Land both files with `land.sh`.



