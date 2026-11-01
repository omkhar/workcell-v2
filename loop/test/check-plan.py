#!/usr/bin/env python3
"""Check loop/state/PLAN.md against its own documented format, then simulate the loop on it.

It reads the clone you are standing in, if that holds loop/PROMPT.md. Otherwise it reads the tree it lies in.
Usage: python3 -I check-plan.py [path/to/PLAN.md]
Standard library only. Exit 0 if every check passes, 1 if any fails, 2 on a usage error.
"""
import collections
import os
import re
import sys

ID = r"(?:[A-Z]-[0-9]+[a-z]?|S-F[0-9]+)"
DEPS = rf"(?:-|above|{ID}(?:,{ID})*)"
UNIT = re.compile(
    rf"^- \[(?P<status>[ x!S])\] (?P<id>{ID})"
    r" \| flow:(?P<flow>mech|doc|escape|build|boundary|spike|audit)"
    r" \| model:(?P<model>haiku|sonnet|opus|fable)"
    r" \| env:(?P<env>any|kvm|macos)"
    rf" \| deps:(?P<deps>{DEPS})"
    r" \| tries:(?P<tries>[0-3])"
    r" \| (?P<sign>sign:you \| )?(?:wait:(?P<wait>[a-z][a-z0-9-]*\.yml) \| )?(?P<title>\S.*)$"
)
GATE = re.compile(
    rf"^- \[(?P<status>[Hx])\] (?P<id>H-[0-9]+[a-z]?)"
    rf" \| env:(?P<env>any|kvm|macos) \| deps:(?P<deps>{DEPS}) \| (?P<title>\S.*)$"
)
ACCEPT = re.compile(r"^      accept: \S.*$")
FIELD_IN_TITLE = re.compile(r"(^| )(flow|model|env|deps|tries|sign|wait):\S")

errors = []


def err(where, text):
    """The plan is a free file, so what is quoted from it is made safe to print on a terminal."""
    errors.append("".join(ch if " " <= ch <= "~" else "?" for ch in f"{where}: {text}"))


def tree():
    """The clone you are standing in, if it holds loop/PROMPT.md. Otherwise the tree that this script lies in."""
    if os.path.isfile(os.path.join("loop", "PROMPT.md")):
        return os.getcwd()
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def parse(path):
    """Every line must be one of: blank, heading, rule, table row, fenced example, prose, unit, gate, accept."""
    print(f"reads {os.path.abspath(path)}")
    with open(path, encoding="utf-8") as handle:
        lines = handle.read().split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    units, kinds, fenced, pending, cutover = [], collections.Counter(), False, None, None
    phase, notes = "", collections.defaultdict(str)
    for number, line in enumerate(lines, 1):
        where = f"line {number}"
        if line != line.rstrip():
            err(where, "trailing blanks")
        if "\t" in line:
            err(where, "a tab")
        if "—" in line or "–" in line:
            err(where, "a long dash")
        if line.startswith("```"):
            fenced = not fenced
            kinds["fence"] += 1
            continue
        if fenced:
            kinds["example"] += 1
            continue
        if pending is not None:
            if ACCEPT.match(line):
                pending["accept"] = line.strip()[len("accept: "):]
                kinds["accept"] += 1
            else:
                err(where, f"{pending['id']} is not followed by its accept line")
            pending = None
            if ACCEPT.match(line):
                continue
        if ACCEPT.match(line):
            err(where, "an accept line with no unit above it")
            continue
        if line == "":
            kinds["blank"] += 1
        elif line.startswith("#"):
            kinds["heading"] += 1
            phase = line
            if line == "## Cutover":
                cutover = len(units)
        elif line == "---":
            kinds["rule"] += 1
        elif line.startswith("|"):
            kinds["table"] += 1
        elif re.match(r"^\s*[-*+]\s*\[", line):
            found = UNIT.match(line) or GATE.match(line)
            if not found:
                err(where, f"does not match the documented line format: {line[:70]}")
                continue
            unit = found.groupdict()
            unit["gate"] = "flow" not in unit
            unit["line"] = number
            unit["sign"] = bool(unit.get("sign"))
            unit["phase"] = phase
            unit["accept"] = ""
            unit.setdefault("wait", None)
            if " | " in unit["title"] or FIELD_IN_TITLE.search(unit["title"]):
                err(where, f"{unit['id']}: the title holds something that looks like a field")
            units.append(unit)
            kinds["gate" if unit["gate"] else "unit"] += 1
            pending = unit
        elif line.startswith(" ") and not re.match(r"^   \S", line):
            err(where, f"indented text that is neither an accept line nor a list continuation: {line[:60]}")
        else:
            kinds["prose"] += 1
            notes[phase] += line + " "
    if fenced:
        err("end of file", "a code fence is still open")
    if pending is not None:
        err("end of file", f"{pending['id']} has no accept line")
    return units, kinds, cutover, notes


def resolve(units):
    """deps as lists of IDs, with 'above' expanded."""
    by_id = {}
    for unit in units:
        if unit["id"] in by_id:
            err(f"line {unit['line']}", f"{unit['id']} appears twice")
        by_id[unit["id"]] = unit
    for position, unit in enumerate(units):
        raw = unit["deps"]
        if raw == "-":
            unit["needs"] = []
        elif raw == "above":
            unit["needs"] = [other["id"] for other in units[:position]]
        else:
            unit["needs"] = raw.split(",")
            if len(set(unit["needs"])) != len(unit["needs"]):
                err(f"line {unit['line']}", f"{unit['id']} names a dependency twice")
        for need in unit["needs"]:
            if need not in by_id:
                err(f"line {unit['line']}", f"{unit['id']} depends on {need}, which does not exist")
            if need == unit["id"]:
                err(f"line {unit['line']}", f"{unit['id']} depends on itself")
        unit["needs"] = [need for need in unit["needs"] if need in by_id and need != unit["id"]]
    return by_id


def find_cycle(by_id):
    state = {}

    def visit(name, trail):
        state[name] = 1
        for need in by_id[name]["needs"]:
            if state.get(need) == 1:
                return trail + [name, need]
            if need not in state:
                found = visit(need, trail + [name])
                if found:
                    return found
        state[name] = 2
        return None

    for name in by_id:
        if name not in state:
            found = visit(name, [])
            if found:
                return found[found.index(found[-1]):]
    return None


def closure(by_id, name):
    seen, stack = set(), list(by_id[name]["needs"])
    while stack:
        need = stack.pop()
        if need not in seen:
            seen.add(need)
            stack.extend(by_id[need]["needs"])
    return seen


def consistency(units, by_id, cutover, notes):
    """Checks that tie the plan to what its own text says."""
    for unit in units:
        where = f"line {unit['line']}"
        if unit["status"] == "S" and not unit["sign"]:
            err(where, f"{unit['id']} is [S] but is not a sign:you unit")
        if not unit["gate"] and unit["id"].startswith("H-"):
            err(where, f"{unit['id']} has a gate's ID and a unit's fields")
    # 1. Whoever adds an invariant to an enforced list depends on the unit that writes its tests, and on the real adapter.
    writes = {}
    for unit in units:
        if unit.get("flow") == "escape" and unit["title"].startswith("Escape tests for "):
            for invariant in re.findall(r"\bI[0-9]+\b", unit["title"].split(":")[0]):
                writes[invariant] = unit["id"]
    for number in range(1, 15):
        if f"I{number}" not in writes:
            err("plan", f"no unit writes the escape tests for I{number}")
    enforced = collections.defaultdict(list)
    for unit in units:
        found = re.match(r"^((?:`?[IPB][0-9]+`?(?:, | and )?)+) added to `(enforced(?:-macos)?\.txt)`", unit["accept"])
        if not found:
            continue
        reach = closure(by_id, unit["id"])
        for entry in re.findall(r"[IPB][0-9]+", found.group(1)):
            enforced[found.group(2)].append(entry)
            if entry in writes and writes[entry] not in reach:
                err(f"line {unit['line']}", f"{unit['id']} enforces {entry} but does not depend on {writes[entry]}, which writes its tests")
        if "U-204b" in by_id and "U-204b" not in reach:
            err(f"line {unit['line']}", f"{unit['id']} enforces something but does not depend on U-204b, the real adapter")
    for number in range(1, 15):
        if enforced["enforced.txt"].count(f"I{number}") != 1:
            err("plan", f"I{number} is added to enforced.txt {enforced['enforced.txt'].count(f'I{number}')} times, not once")
    # 2. Nothing that reads _legacy/ or spikes/ comes after the unit that deletes them.
    sweeper = next((unit for unit in units if unit["title"].startswith("Delete `_legacy/`")), None)
    if sweeper is None:
        err("plan", "no unit deletes _legacy/ and spikes/")
    else:
        reach = closure(by_id, sweeper["id"])
        for unit in units:
            text = unit["title"] + " " + unit["accept"]
            if not unit["gate"] and unit["phase"] != sweeper["phase"]:
                text += " " + notes[unit["phase"]]  # a note at the head of a phase speaks for every unit in it
            if unit is not sweeper and ("_legacy/" in text or "spikes/" in text) and unit["id"] not in reach:
                err(f"line {unit['line']}", f"{unit['id']} uses _legacy/ or spikes/, but {sweeper['id']} does not wait for it")
    # 3. A unit that waits for a workflow depends on the unit that proposes that workflow.
    for unit in units:
        if unit["wait"] and unit["env"] == "macos":
            err(f"line {unit['line']}", f"{unit['id']} waits for a scheduled run, but Mac mode cannot see one")
        if unit["wait"]:
            reach = closure(by_id, unit["id"])
            makers = [other["id"] for other in units if other["sign"] and f"`{unit['wait']}`" in other["title"]]
            if not makers:
                err(f"line {unit['line']}", f"{unit['id']} waits for {unit['wait']}, which no sign:you unit proposes")
            elif not any(maker in reach for maker in makers):
                err(f"line {unit['line']}", f"{unit['id']} waits for {unit['wait']} but depends on none of {', '.join(makers)}")
    # 4. Shape of the end of the plan.
    if "S-1001" in by_id and by_id["S-1001"]["deps"] != "above":
        err("plan", "S-1001 must say deps:above, or Phase 10 can start early")
    if cutover is None:
        err("plan", "there is no '## Cutover' heading")
    else:
        for unit in units[cutover:]:
            if not unit["gate"]:
                err(f"line {unit['line']}", f"{unit['id']} is below '## Cutover' but is not a human gate")
    if units and (units[-1]["id"] != "H-905" or units[-1]["deps"] != "above"):
        err("plan", "the last line must be H-905 with deps:above")
    # 5. A gate on the Mac names the account in its own line, which only the maintainer can change.
    for unit in units:
        if unit["gate"] and unit["env"] == "macos" and not unit["title"].startswith("In the second account: "):
            err(f"line {unit['line']}", f"{unit['id']} is a gate on the Mac, but its title does not start with 'In the second account: '")


def ready(unit, status):
    return all(status[need] == "x" for need in unit["needs"])


def cloud_run(units, status):
    """PROMPT.md section 2, cloud mode: first [ ] unit, top to bottom, env any or kvm, every dependency [x]."""
    done = []
    while True:
        pick = next((u for u in units if not u["gate"] and status[u["id"]] == " " and u["env"] != "macos" and ready(u, status)), None)
        if pick is None:
            return done
        status[pick["id"]] = "S" if pick["sign"] else "x"
        done.append(pick)


def maintainer_turn(units, status):
    """Everything the maintainer can do now: adopt, Mac pieces, gates. Repeats, because one can unlock another."""
    did = []
    moved = True
    while moved:
        moved = False
        for unit in units:
            state = status[unit["id"]]
            if state == "S":
                kind = "adopt"
            elif state == "!":
                status[unit["id"]] = " "  # rewritten, back to [ ] with tries 0; someone still has to do it
                did.append(("rewrite", unit["id"]))
                moved = True
                continue
            elif state == "H" and ready(unit, status):
                kind = "gate"
            elif state == " " and not unit["gate"] and unit["env"] == "macos" and ready(unit, status):
                kind = "mac"
            else:
                continue
            status[unit["id"]] = "x"
            did.append((kind, unit["id"]))
            moved = True
    return did


def names(items):
    return " ".join(items) if items else "(none)"


def tally(title, counter, order):
    print(f"  {title:<9}" + "  ".join(f"{key} {counter.get(key, 0)}" for key in order))


def main():
    if len(sys.argv) > 2:
        print(__doc__, file=sys.stderr)
        return 2
    path = sys.argv[1] if len(sys.argv) == 2 else os.path.join(tree(), "loop", "state", "PLAN.md")
    units, kinds, cutover, notes = parse(path)
    by_id = resolve(units)
    cycle = find_cycle(by_id)
    if cycle:
        err("plan", "dependency cycle: " + " -> ".join(cycle))
    else:
        consistency(units, by_id, cutover, notes)

    print("Lines: " + ", ".join(f"{kinds[k]} {k}" for k in
                                ("unit", "gate", "accept", "heading", "prose", "table", "example", "fence", "rule", "blank")))
    work = [u for u in units if not u["gate"]]
    gates = [u for u in units if u["gate"]]
    todo = [u for u in work if u["status"] != "x"]
    print("\nTallies")
    print(f"  units     {len(work)}: {len(todo)} open, {sum(u['status'] == 'x' for u in work)} done"
          f" ({sum(u['status'] == 'S' for u in work)} proposed, {sum(u['status'] == '!' for u in work)} blocked among the open ones)")
    print(f"  gates     {len(gates)}: {sum(u['status'] == 'H' for u in gates)} open, {sum(u['status'] == 'x' for u in gates)} closed")
    tally("by env", collections.Counter(u["env"] for u in todo), ("any", "kvm", "macos"))
    tally("by model", collections.Counter(u["model"] for u in todo), ("fable", "opus", "sonnet", "haiku"))
    tally("by flow", collections.Counter(u["flow"] for u in todo), ("mech", "doc", "escape", "build", "boundary", "spike", "audit"))
    cloud = [u for u in todo if u["env"] != "macos"]
    print(f"  cloud can take {len(cloud)} of the {len(todo)} open units; the Mac takes the other {len(todo) - len(cloud)}")
    print(f"  sign:you  {sum(u['sign'] for u in todo)}: {names([u['id'] for u in todo if u['sign']])}")
    print(f"  macOS     {sum(u['env'] == 'macos' for u in todo)} units: {names([u['id'] for u in todo if u['env'] == 'macos'])}")
    print(f"            {sum(u['env'] == 'macos' and u['status'] == 'H' for u in gates)} gates: "
          f"{names([u['id'] for u in gates if u['env'] == 'macos' and u['status'] == 'H'])}")
    print(f"  wait:     {names([u['id'] + '(' + u['wait'] + ')' for u in todo if u['wait']])}")
    print(f"  open gates {names([u['id'] for u in gates if u['status'] == 'H'])}")

    if cycle:
        print("\nNo simulation: the plan has a cycle.")
    else:
        status = {u["id"]: u["status"] for u in units}
        if status.get("H-000") == "H":
            status["H-000"] = "x"
            print("\nSimulation (H-000 taken as closed, because the loop starts after setup; every unit passes first time)")
        else:
            print("\nSimulation (every unit passes first time)")
        rounds = 0
        while True:
            ran = cloud_run(units, status)
            rounds += 1
            finished = [u["id"] for u in ran if not u["sign"]]
            proposed = [u["id"] for u in ran if u["sign"]]
            print(f"  cloud stretch {rounds}: {len(finished)} finished, {len(proposed)} proposed")
            print(f"    order: {names([u['id'] + ('[S]' if u['sign'] else '') for u in ran])}")
            did = maintainer_turn(units, status)
            for kind, label in (("adopt", "run adopt.sh"), ("mac", "do a Mac piece"), ("gate", "decide an [H] line"), ("rewrite", "rewrite a unit")):
                if any(k == kind for k, _ in did):
                    print(f"    then the maintainer must {label}: {names([i for k, i in did if k == kind])}")
            if rounds == 1:
                first = (len(finished), len(proposed))
            if not ran and not did:
                break
            if all(state == "x" for state in status.values()):
                break
        stuck = [u["id"] for u in units if status[u["id"]] != "x"]
        if stuck:
            err("plan", "these can never be reached in any mode: " + " ".join(stuck))
        print(f"  The cloud finishes {first[0]} units and proposes {first[1]} more before it first needs the maintainer.")
        print(f"  The loop stops for the maintainer {rounds} times in all, if each stop is used to do everything that is ready.")

    print()
    if errors:
        print(f"FAIL: {len(errors)} problem(s)")
        for text in errors:
            print("  " + text)
        return 1
    print("PASS: every line matches the format; every dependency exists; no cycle; every unit and gate is reachable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
