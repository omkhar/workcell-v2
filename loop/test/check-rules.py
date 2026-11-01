#!/usr/bin/env python3
"""A hand-written model of loop/PROMPT.md sections 0, 2, 6 and 7a, run on a fresh copy of the real PLAN.md.

It cannot read English. So it first checks that PROMPT.md still holds each sentence that it models, word for word.
If one is gone, the model may be out of date, and that is a failure. Then it answers these questions:
  A. one unit that never passes: is it blocked after three tries, and does the loop move on?
  B. everything fails: does the loop halt, stay halted, and start again only after RESUME?
  C. a unit that kills its run: is the first dead run free, and do the next ones count as tries?
  D. two runs that start together: does exactly one of them work?
  E. the hourly trigger fires while a run works: is a second full-price run started?
  F. nothing can merge, or no check appears: does the loop stop without needing a merge?
  G. a unit that waits for a scheduled run: is it skipped without a log entry, and for 48 hours at most?
  H. a unit that needs the maintainer: does the loop halt first, and leave only the neutral record?

It reads the clone you are standing in, if that holds loop/PROMPT.md. Otherwise it reads the tree it lies in.
Usage: python3 -I check-rules.py [path/to/PLAN.md]   Standard library only. Exit 0 if every check holds.
"""
import os
import re
import sys

LINE = re.compile(r"^- \[(.)\] (\S+) \| (.*)$")
failures, reasons = [], set()  # the checks that did not hold; every reason for which the model opened an issue
DONE_AT_START = ("H-000", "U-001", "U-002", "H-104")  # the loop starts after setup; the kit ships the other three as done
NEUTRAL = "needs the maintainer, see the run's transcript"

# What the model below takes from PROMPT.md. Line breaks in the file count as blanks.
ANCHORS = [
    "**C1 is not 0.** The loop is halted. Print `RESULT - HALT` and stop. Open nothing.",
    "is 180 or less, print `RESULT - BUSY` and stop. Otherwise that run is dead.",
    "log FAIL, and end the heading with the words `abandoned run` (7a case 2).",
    "add one to the unit's `tries` only if the unit's previous result line is also an abandoned run.",
    "A `[ ]` unit says `tries:3`. Mark it `[!]`, say why in `loop/state/BLOCKED.md`, and log BLOCKED (7a case 2).",
    "| tail -n 6` prints six lines, and each says FAIL or BLOCKED. The result is HALT, reason `six-failures`.",
    "A RESUME line among them ends the streak.",
    "Every unit and gate above the heading `## Cutover` is `[x]`. The result is DONE.",
    "the first unit, top to bottom, that is `[ ]`, has every dependency `[x]`, and that your mode may take.",
    "`[S]`, `[!]` and `[H]` are not finished. Never take an `[H]` line.",
    "Skip a unit with `wait:<file>` until C7 shows a finished scheduled run of that workflow",
    "Nothing qualifies, but a unit whose dependencies are all `[x]` was skipped only because of `wait:`.",
    "the age of the newest commit on `main` is how long it has waited.",
    "Up to 172800 seconds, which is 48 hours, print `RESULT <unit> BUSY` and stop: no claim, no log, no issue.",
    "Above that, the schedule is broken: HALT, reason `no-schedule`.",
    "Nothing qualifies. The result is HALT, reason `nothing-to-do`.",
    "pull request with a lower number, you lost a race: close yours, print `RESULT - BUSY` and stop.",
    "Set the unit to `[x]` (or `[S]`, section 3). If it failed, leave it `[ ]` and add one to `tries`.",
    "Open a halt issue with reason `needs-you` first, so that no other run starts. Mark the unit `[!]` and log BLOCKED.",
    "write only `<unit>: " + NEUTRAL + "`. Then deliver as in 7a case 2, and watch that pull request merge. "
    "Case 3 does not apply: the issue is open already, and closing the pull request would lose the record. The result is HALT.",
    "only the maintainer can do it. Follow section 6, rule 5.",
    "has not appeared 15 minutes after a push, or has not finished after 45 | HALT, reason `no-checks` |",
    "| a case 2 pull request has not merged after 30 minutes | HALT, reason `no-merge` |",
    "For DONE the reason is `finished`.",
]


def tree():
    """The clone you are standing in, if it holds loop/PROMPT.md. Otherwise the tree that this script lies in."""
    if os.path.isfile(os.path.join("loop", "PROMPT.md")):
        return os.getcwd()
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def read(path):
    print(f"reads {os.path.abspath(path)}")
    with open(path, encoding="utf-8") as handle:
        return handle.read()


class World:
    """main (plan and log), open pull requests and open halt issues. Time is in minutes."""

    def __init__(self, plan):
        self.units = []
        self.cutover = None
        for line in plan.split("\n"):
            if line == "## Cutover":
                self.cutover = len(self.units)
            found = LINE.match(line)
            if not found:
                continue
            fields = dict(f.split(":", 1) for f in found.group(3).split(" | ") if re.match(r"^(flow|env|deps|tries|sign|wait):", f))
            gate = "flow" not in fields
            # A private copy, as it was before the first run, whatever the loop has done to the real plan since.
            self.units.append({"status": "x" if found.group(2) in DONE_AT_START else "H" if gate else " ", "id": found.group(2),
                               "env": fields["env"], "deps": fields["deps"], "tries": 0, "gate": gate,
                               "sign": "sign" in fields, "wait": fields.get("wait")})
        self.log, self.blocked, self.pulls, self.issues = [], [], [], []
        self.now, self.tip, self.number, self.full_price = 0, 0, 0, 0  # tip: when the newest commit on main was made
        self.ci_up, self.merges, self.nightly_done = True, True, False

    def unit(self, name):
        return next(u for u in self.units if u["id"] == name)

    def ready(self, unit):
        if unit["deps"] == "-":
            return True
        if unit["deps"] == "above":
            return all(u["status"] == "x" for u in self.units[:self.units.index(unit)])
        return all(self.unit(d)["status"] == "x" for d in unit["deps"].split(","))

    def open_pull(self, unit, title):
        self.number += 1
        pull = {"n": self.number, "unit": unit, "title": title, "touched": self.now}
        self.pulls.append(pull)
        return pull

    def halt(self, reason):
        self.issues.append(reason)
        reasons.add(reason)
        return f"HALT {reason}"

    def land(self, *entries):
        self.log += entries
        self.tip = self.now

    def last_result(self, name):
        return next((word for unit, word in reversed(self.log) if unit == name and word != "START"), "")


def deliver_state(world, unit, word, change):
    """7a case 2: a pull request that holds only loop/state/. It needs a merge, so it can fail to land."""
    pull = world.open_pull(unit["id"], f"{unit['id']}: {word}")
    if not world.ci_up:
        world.pulls.remove(pull)
        return world.halt("no-checks")
    if not world.merges:
        world.pulls.remove(pull)
        return world.halt("no-merge")
    change()
    world.land((unit["id"], word))
    world.pulls.remove(pull)
    return f"{unit['id']} {word}"


def run(world, outcome, rival=False):
    """One iteration in cloud mode. outcome(unit id) is 'pass', 'fail', 'die', 'working' or 'needs-you'. Returns the RESULT line."""
    # Section 0.
    if world.issues:
        return "- HALT"
    for pull in list(world.pulls):
        if world.now - pull["touched"] <= 180:
            return "- BUSY"
        world.pulls.remove(pull)  # dead: close it, and record it
        unit = world.unit(pull["unit"])
        more = 1 if world.last_result(unit["id"]) == "FAIL abandoned run" else 0
        return deliver_state(world, unit, "FAIL abandoned run", lambda: unit.__setitem__("tries", unit["tries"] + more))
    # Section 2, in order.
    for unit in world.units:
        if unit["status"] == " " and unit["tries"] >= 3:
            return deliver_state(world, unit, "BLOCKED", lambda: unit.__setitem__("status", "!"))
    results = [word.split()[0] for _, word in world.log if word != "START"][-6:]
    if len(results) == 6 and all(word in ("FAIL", "BLOCKED") for word in results):
        return world.halt("six-failures")
    if all(u["status"] == "x" for u in world.units[:world.cutover]):
        return world.halt("finished").replace("HALT", "DONE")
    waiting, pick = None, None
    for unit in world.units:
        if unit["gate"] or unit["status"] != " " or unit["env"] == "macos" or not world.ready(unit):
            continue
        if unit["wait"] and not world.nightly_done:
            waiting = waiting or unit
            continue
        pick = unit
        break
    if pick is None and waiting:
        return f"{waiting['id']} BUSY" if world.now - world.tip <= 48 * 60 else world.halt("no-schedule")
    if pick is None:
        return world.halt("nothing-to-do")
    # Claim.
    claim = world.open_pull(pick["id"], f"try: {pick['id']}")
    if rival or any(p["n"] < claim["n"] for p in world.pulls):
        world.pulls.remove(claim)
        return "- BUSY"
    if not world.ci_up:
        world.pulls.remove(claim)
        return world.halt("no-checks")
    # Work.
    world.full_price += 1
    what = outcome(pick["id"])
    if what == "die":
        return "(the run died)"
    if what == "working":
        return "(still working)"
    if what == "needs-you":  # section 6, rule 5: the issue first
        verdict = world.halt("needs-you")
        world.blocked.append(f"{pick['id']}: {NEUTRAL}")
        deliver_state(world, pick, "BLOCKED", lambda: pick.__setitem__("status", "!"))
        world.pulls.remove(claim)
        return verdict
    world.pulls.remove(claim)
    if what == "fail":
        return deliver_state(world, pick, "FAIL", lambda: pick.__setitem__("tries", pick["tries"] + 1))
    if not world.merges:
        return world.halt("no-merge")
    pick["status"] = "S" if pick["sign"] else "x"
    world.land((pick["id"], "START"), (pick["id"], "PASS"))
    return f"{pick['id']} PASS"


def expect(label, condition, detail=""):
    detail = "".join(ch if " " <= ch <= "~" else "?" for ch in detail)  # it may quote the plan, which is a free file
    print(("ok    " if condition else "FAIL  ") + label + (f"  [{detail}]" if detail else ""))
    if not condition:
        failures.append(label)


def main():
    if len(sys.argv) > 2:
        print(__doc__, file=sys.stderr)
        return 2
    root = tree()
    prompt = " ".join(read(os.path.join(root, "loop", "PROMPT.md")).split())
    plan = read(sys.argv[1] if len(sys.argv) == 2 else os.path.join(root, "loop", "state", "PLAN.md"))

    print("0. PROMPT.md still says what this model assumes")
    for sentence in ANCHORS:
        expect(sentence[:100], sentence in prompt)

    print("A. U-004 never passes; everything else does")
    w = World(plan)
    trace = []
    while "U-004 BLOCKED" not in trace[:-1] and len(trace) < 60 and not w.issues:  # units split off or added may come first
        trace.append(run(w, lambda u: "fail" if u == "U-004" else "pass"))
    expect("three FAILs, then BLOCKED, with no halt", trace[-5:-1] == ["U-004 FAIL"] * 3 + ["U-004 BLOCKED"], " / ".join(trace))
    expect("the loop moves on to the next unit that does not need U-004", trace[-1].endswith(" PASS"), trace[-1])
    expect("U-004 is [!] with tries 3", (w.unit("U-004")["status"], w.unit("U-004")["tries"]) == ("!", 3))
    last = ""
    while not w.issues:
        last = run(w, lambda u: "pass")
    passes = sum(1 for _, word in w.log if word == "PASS")
    expect("it halts only when nothing is left to do", last == "HALT nothing-to-do", f"{passes} units passed first")
    unmet = [u["id"] for u in w.units if u["wait"] and u["status"] == " " and not w.ready(u)]
    expect("a wait: unit whose dependencies are not met does not turn that halt into BUSY", len(unmet) > 0, " ".join(unmet))
    w.unit("U-004").update(status=" ", tries=0)  # BLOCKED.md: back to [ ] and tries 0
    w.issues.clear()
    expect("after the maintainer resets it, the unit is tried again, not blocked again", run(w, lambda u: "pass") == "U-004 PASS")

    print("B. every unit fails")
    w = World(plan)
    trace = []
    while not w.issues:
        trace.append(run(w, lambda u: "fail"))
    expect("the loop halts on the seventh run, after six results", len(trace) == 7 and trace[-1] == "HALT six-failures", " / ".join(trace))
    expect("that costs five full-price runs; the sixth result only marked a unit [!]", w.full_price == 5, f"{w.full_price} full-price runs")
    expect("further runs stop at once while the issue is open", [run(w, lambda u: "fail") for _ in range(3)] == ["- HALT"] * 3)
    w.issues.clear()
    expect("closing the issue alone does not clear it", run(w, lambda u: "pass") == "HALT six-failures")
    w.issues.clear()
    w.land(("-", "RESUME"))
    after = run(w, lambda u: "pass")
    expect("a RESUME line clears it", after.endswith("PASS"), after)
    trace = []
    while not w.issues:
        trace.append(run(w, lambda u: "fail"))
    expect("after RESUME it takes six new failures to halt again", len(trace) == 7, " / ".join(trace))

    print("C. U-003 kills its run")
    w = World(plan)
    trace, tries = [], []
    for hour in range(0, 60):
        w.now = hour * 60
        trace.append(run(w, lambda u: "die" if u == "U-003" else "pass"))
        if trace[-1] == "U-003 FAIL abandoned run":
            tries.append(w.unit("U-003")["tries"])
        if w.unit("U-003")["status"] == "!":
            break
    at = trace.index("(the run died)") if "(the run died)" in trace else 0
    expect("a dead run is closed after three hours and logged", trace[at:at + 5] == ["(the run died)"] + ["- BUSY"] * 3 + ["U-003 FAIL abandoned run"],
           " / ".join(trace[:at + 6]))
    expect("the first dead run uses up no try; each one that follows it does", tries == [0, 1, 2, 3], str(tries))
    expect("the unit is blocked in the end, so it cannot be restarted for ever", w.unit("U-003")["status"] == "!" and not w.issues)
    w = World(plan)
    deaths = ["die"]
    for hour in range(0, 24):
        w.now = hour * 60
        run(w, lambda u: deaths.pop() if u == "U-003" and deaths else "pass")
    expect("one run lost to a usage limit costs a healthy unit nothing", (w.unit("U-003")["status"], w.unit("U-003")["tries"]) == ("x", 0))
    w = World(plan)
    script = ["die", "fail", "die"]
    for hour in range(0, 40):
        w.now = hour * 60
        if run(w, lambda u: script.pop() if u == "U-003" and script else "working" if u == "U-003" else "pass") == "U-003 FAIL abandoned run" and not script:
            break
    expect("a dead run after an ordinary FAIL is a first one again", w.unit("U-003")["tries"] == 1 and not script,
           " / ".join(word for unit, word in w.log if unit == "U-003" and word != "START"))

    print("D. two runs start in the same minute")
    w = World(plan)
    first = w.open_pull("U-002b", "try: U-002b")  # the rival's claim got the lower number
    mine = run(w, lambda u: "pass")
    expect("a run that sees the rival's claim prints BUSY", mine == "- BUSY")
    w.pulls.remove(first)
    w2 = World(plan)
    expect("a run that loses the race after claiming closes its claim", run(w2, lambda u: "pass", rival=True) == "- BUSY" and not w2.pulls)
    expect("the loser did no full-price work", w2.full_price == 0)

    print("E. the hourly trigger fires while a run is working")
    w = World(plan)
    run(w, lambda u: "working")
    w.now = 45
    expect("the second run sees the claim and stops", run(w, lambda u: "pass") == "- BUSY" and w.full_price == 1)

    print("F. delivery itself is broken")
    w = World(plan)
    w.ci_up = False
    expect("no check appears: halt before any work, with no merge needed", run(w, lambda u: "pass") == "HALT no-checks" and w.full_price == 0)
    expect("later runs cost nothing", run(w, lambda u: "pass") == "- HALT" and w.full_price == 0 and not w.pulls)
    w = World(plan)
    w.merges = False
    expect("checks run but nothing merges: one run, then halt", run(w, lambda u: "fail") == "HALT no-merge" and not w.pulls)
    expect("no second full-price run", run(w, lambda u: "fail") == "- HALT" and w.full_price == 1)

    print("G. a unit that waits for a scheduled run")
    w = World(plan)
    for unit in w.units:  # everything up to W-802 is done and adopted
        if unit["id"] == "W-802b":
            break
        unit["status"] = "x"
    for name in ("W-803", "W-804", "H-806"):
        w.unit(name)["status"] = "x"
    order = [run(w, lambda u: "pass") for _ in range(3)]
    expect("W-802b is skipped, not failed, and other units go first", "W-802b" not in " ".join(order), " / ".join(order))
    before = len(w.log)
    while True:
        w.now += 30
        last = run(w, lambda u: "pass")
        if last.endswith("BUSY") or w.issues:
            break
    expect("when only waiting units are left: BUSY, no issue, no claim", last == "W-802b BUSY" and not w.issues and not w.pulls, last)
    size = len(w.log)
    w.now = w.tip + 48 * 60
    expect("it is still BUSY after 48 hours", run(w, lambda u: "pass") == "W-802b BUSY" and not w.issues)
    expect("waiting writes nothing to the log", len(w.log) == size and size >= before)
    w.now += 60
    expect("an hour later the loop says that the schedule is broken", run(w, lambda u: "pass") == "HALT no-schedule" and not w.pulls)
    expect("and stays halted", run(w, lambda u: "pass") == "- HALT" and len(w.log) == size)
    w.nightly_done = True  # the maintainer repairs the schedule, waits for one run of it, and closes the issue
    w.issues.clear()
    expect("once the run has finished the unit is taken", run(w, lambda u: "pass") == "W-802b PASS")

    print("H. U-302 needs the maintainer, for a reason that is not said in public")
    w = World(plan)
    trace = []
    while not w.issues:
        trace.append(run(w, lambda u: "needs-you" if u == "U-302" else "pass"))
    expect("the loop halts with the one neutral reason", trace[-1] == "HALT needs-you" and w.issues == ["needs-you"], trace[-1])
    expect("the unit is [!], logged as BLOCKED, and no try is used up",
           (w.unit("U-302")["status"], w.unit("U-302")["tries"], w.log[-1]) == ("!", 0, ("U-302", "BLOCKED")))
    expect("the public record is the neutral sentence and nothing else", w.blocked == [f"U-302: {NEUTRAL}"], " / ".join(w.blocked))
    expect("no pull request is left open, and later runs stop at once", not w.pulls and run(w, lambda u: "pass") == "- HALT")

    print("Z. every reason the model gave is on the list in section 7a")
    listed = re.search(r"For HALT it is one of (.*?), and no other\.", prompt)
    names = set(re.findall(r"`([a-z-]+)`", listed.group(1))) if listed else set()
    expect("PROMPT.md lists the reasons for HALT", len(names) >= 10, " ".join(sorted(names)))
    expect("each of the model's reasons is on it", len(reasons) >= 6 and reasons - {"finished"} <= names, " ".join(sorted(reasons)))

    print()
    if failures:
        print(f"FAIL: {len(failures)} check(s)")
        return 1
    print(f"PASS: a model of PROMPT.md blocks, halts, resumes, waits and stops as intended, and PROMPT.md still holds the {len(ANCHORS)} sentences it models")
    return 0


if __name__ == "__main__":
    sys.exit(main())
