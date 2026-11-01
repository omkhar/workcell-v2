#!/usr/bin/env python3
"""Show that check-plan.py can fail: break PLAN.md in one way at a time and expect the matching complaint.

It reads the plan of the clone you are standing in, if that holds loop/PROMPT.md. Otherwise it reads the tree it lies in.
It always runs the check-plan.py beside itself. It breaks a private copy in which every unit and gate is open again, so
that the loop's progress does not hide the text to break.
Usage: python3 -I check-plan-selftest.py   Standard library only. Exit 0 if every mutation is caught.
"""
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

MUTATIONS = [
    # (label, old text, new text, words expected in the complaint)
    ("a field is missing", "- [ ] U-003 | flow:mech | model:haiku |", "- [ ] U-003 | flow:mech |", "does not match the documented line format"),
    ("an unknown flow", "- [ ] U-003 | flow:mech |", "- [ ] U-003 | flow:magic |", "does not match the documented line format"),
    ("an unknown status", "- [ ] U-003 |", "- [?] U-003 |", "does not match the documented line format"),
    ("tries out of range", "U-003 | flow:mech | model:haiku | env:any | deps:H-000 | tries:0", "U-003 | flow:mech | model:haiku | env:any | deps:H-000 | tries:4", "does not match the documented line format"),
    ("the old keyword deps:all", "- [H] H-905 | env:any | deps:above |", "- [H] H-905 | env:any | deps:all |", "does not match the documented line format"),
    ("a gate with a unit's fields", "- [H] H-103 | env:any |", "- [H] H-103 | flow:mech | model:opus | env:any |", "does not match the documented line format"),
    ("a dependency that does not exist", "deps:U-303,U-006", "deps:U-303,U-999", "depends on U-999, which does not exist"),
    ("the deleted unit W-805", "deps:U-005,U-006,U-007,U-008,U-009,U-010,U-010b |", "deps:W-805 |", "depends on W-805, which does not exist"),
    ("a cycle", "- [ ] U-004 | flow:escape | model:fable | env:any | deps:U-001 |", "- [ ] U-004 | flow:escape | model:fable | env:any | deps:U-204b |", "dependency cycle"),
    ("a cycle through deps:above", "- [ ] U-900 | flow:doc | model:sonnet | env:kvm | deps:U-603 |", "- [ ] U-900 | flow:doc | model:sonnet | env:kvm | deps:S-1001 |", "dependency cycle"),
    ("an ID used twice", "- [ ] U-006 |", "- [ ] U-005 |", "U-005 appears twice"),
    ("a lost accept line", "      accept: as U-404\n- [ ] U-406", "- [ ] U-406", "is not followed by its accept line"),
    ("[S] on a unit that needs no signature", "- [ ] U-003 |", "- [S] U-003 |", "is [S] but is not a sign:you unit"),
    ("Phase 10 with the thin dependencies of version 3", "- [ ] S-1001 | flow:audit | model:fable | env:any | deps:above |", "- [ ] S-1001 | flow:audit | model:fable | env:any | deps:U-905a,H-703,H-704 |", "S-1001 must say deps:above"),
    ("a unit that waits for a gate of the cutover", "| deps:B-820,B-825,U-408,U-010b |", "| deps:B-820,B-825,U-408,U-010b,H-829 |", "dependency cycle"),
    ("an enforcing unit without its tests", "deps:U-204b,U-007 | tries:0 | Resource caps", "deps:U-204b | tries:0 | Resource caps", "enforces I10 but does not depend on U-007"),
    ("an enforcing unit without the real adapter", "deps:U-204b,U-007 | tries:0 | Resource caps", "deps:U-204,U-007 | tries:0 | Resource caps", "does not depend on U-204b"),
    ("_legacy/ deleted before the migration guide reads it", "deps:U-903,U-600,", "deps:U-600,", "U-903 uses _legacy/ or spikes/"),
    ("_legacy/bump/ deleted before Phase 8b is over", "B-826b,B-827,B-828 |", "B-826b,B-828 |", "B-827 uses _legacy/ or spikes/"),
    ("spikes/ deleted before the Mac needs it", "U-205,U-701,U-702,", "U-205,U-702,", "U-701 uses _legacy/ or spikes/"),
    ("a wait on a workflow that nobody proposes", "wait:release.yml |", "wait:weekly.yml |", "which no sign:you unit proposes"),
    ("a collector that does not depend on the workflow", "- [ ] S-1014a | flow:mech | model:haiku | env:any | deps:S-1001,W-802b |", "- [ ] S-1014a | flow:mech | model:haiku | env:any | deps:U-001 |", None),
    ("a unit below the Cutover heading", "- [H] H-807 | env:any | deps:H-1019 |", "- [ ] U-909 | flow:mech | model:haiku | env:any | deps:H-1019 | tries:0 |", "is not a human gate"),
    ("a Mac unit that waits for a scheduled run", "- [ ] W-801b | flow:mech | model:haiku | env:kvm |", "- [ ] W-801b | flow:mech | model:haiku | env:macos |", "Mac mode cannot see one"),
    ("a long dash", "## Phase 1: choose the VM layer", "## Phase 1 — choose the VM layer", "a long dash"),
    ("a field inside a title", "| tries:0 | Detach and `attach`", "| tries:0 | env:kvm Detach and `attach`", "looks like a field"),
    ("a gate on the Mac that does not name the account", "| In the second account: run the full suite on a real Mac.", "| Run the full suite on a real Mac.", "does not start with 'In the second account: '"),
]


def tree():
    """The clone you are standing in, if it holds loop/PROMPT.md. Otherwise the tree that this script lies in."""
    if os.path.isfile(os.path.join("loop", "PROMPT.md")):
        return os.getcwd()
    return os.path.dirname(os.path.dirname(HERE))


def fresh(plan):
    """The same plan with every unit and gate open again, and no try used up."""
    plan = re.sub(r"(?m)^- \[[x!S]\] (?=[A-Z]-[0-9F])", "- [ ] ", plan)
    plan = re.sub(r"(?m)^- \[ \] (?=H-[0-9]+[a-z]? \| env:)", "- [H] ", plan)
    return re.sub(r"(?m)^(- \[ \] .*? \| tries:)[0-3] ", r"\g<1>0 ", plan)


def check(text):
    with tempfile.TemporaryDirectory() as folder:
        path = os.path.join(folder, "PLAN.md")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(text)
        done = subprocess.run([sys.executable, "-I", os.path.join(HERE, "check-plan.py"), path],
                              capture_output=True, text=True, check=False)
        return done.returncode, done.stdout


def main():
    path = os.path.join(tree(), "loop", "state", "PLAN.md")
    print(f"reads {os.path.abspath(path)}")
    with open(path, encoding="utf-8") as handle:
        plan = handle.read()
    missed = 0
    for label, text in (("the plan as it stands passes", plan), ("so does the copy in which everything is open again", fresh(plan))):
        code, _ = check(text)
        print(("ok    " if code == 0 else "FAIL  ") + label)
        missed += 0 if code == 0 else 1
    plan = fresh(plan)
    for label, old, new, words in MUTATIONS:
        if plan.count(old) != 1:
            print(f"FAIL  {label}: the text to break occurs {plan.count(old)} times")
            missed += 1
            continue
        code, output = check(plan.replace(old, new))
        caught = code == 1 and (words is None or words in output)
        complaint = next((line.strip() for line in output.split("\n") if line.startswith("  line") or line.startswith("  plan")), "")
        print(("ok    " if caught else "FAIL  ") + f"{label}: {complaint[:120]}")
        missed += 0 if caught else 1
    print()
    if missed:
        print(f"FAIL: {missed}")
        return 1
    print(f"PASS: all {len(MUTATIONS)} mutations are caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())
