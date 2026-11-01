#!/usr/bin/env python3
"""Check .claude/settings.json (loop/claude-settings.json until setup-1 has run) against loop/PROMPT.md.

It emulates the documented matching of Bash deny rules (code.claude.com/docs/en/permissions):
a rule matches the whole text of one subcommand; `*` stands for any text, spaces included; a
single trailing ` *` also matches the bare command; compound commands are split at && || ; | |& &
and newlines; leading variable assignments and a few wrappers are stripped.

It emulates the documented matching of Edit deny rules too (same page): gitignore syntax; in project settings a rule
that starts with one slash is anchored at the repository root; `*` stays inside one path segment and `**` crosses them.

1. No command that PROMPT.md tells the orchestrator to run may be denied. The same holds for the commands that
   START-HERE.md steps 5c and 5d hand to a cloud session: a test that a rule stops would prove nothing.
2. Every command on the "never" list below must be denied.
3. Every path on the "locked" list below must be blocked for the file tools, and no free path may be.
4. The file must hold no availableModels, must keep the fallback order the maintainer asked for, and must not say what
   the alias fable stands for: that is set in the cloud environment, and on the command line in the second account.

It reads the clone you are standing in, if that holds loop/PROMPT.md. Otherwise it reads the tree it lies in.
Usage: python3 -I check-deny.py [settings.json]    Standard library only. Exit 0 if all is well.
"""
import json
import os
import re
import sys


def tree():
    """The clone you are standing in, if it holds loop/PROMPT.md. Otherwise the tree that this script lies in."""
    if os.path.isfile(os.path.join("loop", "PROMPT.md")):
        return os.getcwd()
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def read(path):
    print(f"reads {os.path.abspath(path)}")
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def split(command):
    """Subcommands of a compound command. Quotes are respected; redirections stay with their command."""
    parts, current, quote, i = [], "", None, 0
    while i < len(command):
        ch = command[i]
        if quote:
            current += ch
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
            current += ch
        elif command[i:i + 2] in ("&&", "||", "|&"):
            parts.append(current)
            current, i = "", i + 1
        elif ch in ";|&\n":
            parts.append(current)
            current = ""
        else:
            current += ch
        i += 1
    parts.append(current)
    cleaned = []
    for part in parts:
        part = part.strip()
        changed = True
        while changed:
            changed = False
            found = re.match(r"^[A-Za-z_][A-Za-z0-9_]*=\S*\s+(.*)$", part, re.S)
            if found:
                part, changed = found.group(1), True
            found = re.match(r"^(?:timeout \S+|time|nice|nohup|stdbuf|command|builtin|noglob)\s+(.*)$", part, re.S)
            if found:
                part, changed = found.group(1), True
        if part:
            cleaned.append(part)
    return cleaned


def to_regex(rule):
    body = "".join(".*" if ch == "*" else re.escape(ch) for ch in rule)
    if rule.endswith(" *") and rule.count("*") == 1:
        body = re.escape(rule[:-2]) + r"(?: .*)?"
    return re.compile("^" + body + "$", re.S)


def edit_regex(rule):
    """An Edit rule that starts with one slash, as a pattern over paths relative to the repository root."""
    parts, out = rule[1:].split("/"), ""
    for number, part in enumerate(parts):
        last = number == len(parts) - 1
        if part == "**":
            out += ".*" if last else "(?:.*/)?"
            continue
        out += "".join("[^/]*" if ch == "*" else "[^/]" if ch == "?" else re.escape(ch) for ch in re.sub(r"\*+", "*", part))
        out += "" if last else "/"
    return re.compile("^" + out + "(?:/.*)?$")  # a directory that matches takes its content with it


def main():
    root = tree()
    final = os.path.join(root, ".claude", "settings.json")
    packed = os.path.join(root, "loop", "claude-settings.json")
    path = sys.argv[1] if len(sys.argv) == 2 else packed if os.path.exists(packed) else final
    settings = json.loads(read(path))
    prompt = read(os.path.join(root, "loop", "PROMPT.md"))
    rules = [r[5:-1] for r in settings["permissions"]["deny"] if r.startswith("Bash(")]
    compiled = [(rule, to_regex(rule)) for rule in rules]

    def denied_by(command):
        return [rule for part in split(command) for rule, regex in compiled if regex.match(part)]

    problems = []

    # 1. What the prompt asks for.
    wanted = []
    for line in prompt.split("\n"):
        found = re.match(r"^- \*\*C[0-9]\*\*.*?[:.] `(g(?:h|it) .*)`$", line)
        if found:
            wanted.append(found.group(1))
    fenced = re.findall(r"```bash\n(.*?)```", prompt, re.S)
    wanted += [line for block in fenced for line in block.strip().split("\n")]
    wanted += re.findall(r"`((?:git|grep|echo|date|loop/gate\.sh|loop/guard\.sh|GATE_MACOS=1) [^`]*|loop/gate\.sh)`", prompt)
    filled = []
    for command in dict.fromkeys(wanted):
        command = command.replace("/SHA/", "/0123abcd/").replace("pulls/N", "pulls/12").replace("/ID", "/987")
        command = command.replace("<unit>", "S-1007").replace("<time>", "20261031T101500Z")
        command = command.replace("<imperative summary>", "audit secrets, hooks and rulesets")
        filled.append(command)
    if len(filled) < 25:
        problems.append(f"only {len(filled)} commands were found in PROMPT.md; the extraction is broken")
    for command in filled:
        hit = denied_by(command)
        if hit:
            problems.append(f"PROMPT.md needs this, but it is denied by {hit}: {command[:110]}")

    guide = read(os.path.join(root, "loop", "START-HERE.md"))
    start, end = guide.find("### 5c"), guide.find("## Step 6")
    cloud = guide[start:end] if 0 <= start < end else ""  # nothing, if either heading is gone
    pasted = re.findall(r"(?:gh api|git fetch) [^\n]*", "\n".join(re.findall(r"```text\n(.*?)```", cloud, re.S)))
    if len(pasted) < 6:
        problems.append(f"only {len(pasted)} commands were found in START-HERE.md steps 5c and 5d; the extraction is broken")
    for command in pasted:
        hit = denied_by(command.replace("/SHA/", "/0123abc/").replace("/ID/", "/123/"))
        if hit:
            problems.append(f"START-HERE.md needs this, but it is denied by {hit}: {command[:110]}")

    # 2. What must never run.
    slug = "repos/omkhar/workcell-v2"
    never = [
        "git push origin main", "git push origin work:main", "git push origin HEAD:main",
        "git push origin HEAD:refs/heads/main", "git push -f origin HEAD:refs/heads/claude/x",
        "git push origin --force HEAD:refs/heads/claude/x", "git push --force-with-lease origin x",
        "git push origin +HEAD:refs/heads/claude/x", "git push origin :refs/heads/claude/x",
        "git push origin --delete claude/x", "git push --tags", "git push origin refs/tags/v2.0.0",
        "git push origin HEAD:refs/tags/loop-checkpoint-9", "git push origin HEAD:refs/checkpoints/loop-checkpoint-9",
        "git push origin refs/tags/loop-checkpoint-9:refs/checkpoints/loop-checkpoint-9", "git push --mirror origin", "git push --all origin",
        "cd /tmp && git push origin HEAD:main", "FOO=1 git push origin main", "timeout 30 git push origin main",
        "git tag v2.0.0", "git remote add x https://example.com/x.git", "git config user.name x",
        f"gh api {slug}/check-runs -f name=gate", f"gh api {slug}/check-runs -X POST -f name=gate",
        f"gh api -X POST {slug}/check-runs --input x.json", f"gh api --input x.json {slug}/check-runs",
        f'gh api "{slug}/check-runs" --input x.json', f"gh api -X PATCH {slug}/check-runs/5 --input x.json",
        f"gh api {slug}/check-runs/5 --method PATCH --input x.json",
        f"gh api -X POST {slug}/statuses/abc --input x.json", f"gh api -X POST {slug}/git/refs --input x.json",
        f"gh api {slug}/git/refs -f ref=refs/tags/x -f sha=abc", f"gh api -X POST {slug}/releases --input x.json",
        f"gh api -X PUT {slug}/pulls/3/merge", f"gh api {slug}/pulls/3/merge -X PUT", f"gh api --method PUT {slug}/pulls/3/merge",
        f"gh api {slug}/pulls/3/merge --input x.json", f"gh api -X POST {slug}/merges --input x.json",
        f"gh api -X DELETE {slug}/actions/runs/5", f"gh api {slug}/actions/runs/5 --method DELETE",
        f"gh api -X POST {slug}/actions/runs/5/rerun", f"gh api -X POST {slug}/actions/runs/5/cancel",
        f"gh api -X POST {slug}/actions/workflows/ci.yml/dispatches --input x.json",
        f"gh api -X POST {slug}/dispatches --input x.json", f"gh api -X POST {slug}/hooks --input x.json",
        f"gh api -X POST {slug}/rulesets --input x.json", f"gh api -X POST {slug}/actions/policies --input x.json",
        f"gh api {slug}/actions/policies --input x.json", f"gh api --input x.json {slug}/actions/policies",
        f"gh api --method POST {slug}/actions/policies", f"gh api {slug}/actions/policies -X POST",
        f"gh api -X PUT {slug}/actions/policies/5 --input x.json", f"gh api {slug}/actions/policies/5 --method DELETE",
        f"gh api {slug}/actions/policies -f name=x", f'gh api "{slug}/actions/policies" --input -',
        f"gh api {slug}/actions/secrets/public-key", f"gh api -X PUT {slug}/branches/main/protection --input x.json",
        f"gh api -X PUT {slug}/contents/.github/workflows/x.yml --input x.json",
        f"gh api -X PUT {slug}/interaction-limits --input x.json", f"gh api -X PUT {slug}/environments/bump",
        "gh api repos/{owner}/{repo}/pulls", "gh api graphql --input q.json",
        f"gh api https://api.github.com/{slug}/hooks --input x.json",
        "gh workflow run ci.yml", "gh run rerun 5", "gh run view 5 --log", "gh release create v2", "gh secret set X",
        "gh variable set X", "gh repo edit --visibility private", "gh auth token", "gh ruleset list", "gpg --list-secret-keys",
    ]
    for command in never:
        if not denied_by(command):
            problems.append(f"this must be denied, and is not: {command}")

    # 3. What the file tools may not touch, and what they must be able to touch.
    locked = [
        ".github/workflows/ci.yml", ".github/workflows/guard.yml", ".github/workflows/new.yml", ".github/zizmor.yml",
        ".github/dependabot.yml", ".github/maintainer.asc", ".github/maintainer.fpr", ".github/CODEOWNERS",
        ".claude/settings.json", ".claude/settings.local.json", ".claude/agents/builder.md", ".claude/skills/x/SKILL.md",
        ".gitignore", ".gitattributes", "CLAUDE.md",
        "loop/PROMPT.md", "loop/SPEC.md", "loop/REFERENCE.md", "loop/START-HERE.md", "loop/WORKFLOW-REVIEW.md", "loop/PR-BODY.md",
        "loop/gate.sh", "loop/guard.sh", "loop/lib.sh", "loop/land.sh", "loop/adopt.sh", "loop/checkpoint.sh", "loop/settings.sh",
        "loop/preflight.sh", "loop/baseline-ci.sh", "loop/setup-1-open-pr.sh", "loop/setup-2-after-merge.sh",
        "loop/free-paths.txt", "loop/github-main.json", "loop/github-tags-all.json", "loop/github-actions-policy.json",
        "loop/test/all.sh", "loop/test/suite.sh", "loop/test/fake-gh", "loop/test/check-deny.py",
    ]
    free = [
        "cmd/workcell/main.go", "internal/proxy/proxy.go", "escape/enforced.txt", "escape/fuzz-minutes.txt",
        "escape/_pending/S-F1/x_test.go", "pins/claude.toml", "docs/benchmarks.md", "docs/adr/001-vmm.md", "spikes/libkrun/boot_test.go",
        "proposed/dot-github/workflows/ci.yml", "proposed/CLAUDE.md.txt", "proposed/loop/gate.sh", "_legacy/flags.txt",
        "loop/state/PLAN.md", "loop/state/LOG.md", "loop/state/BLOCKED.md", "loop/state/PARKED.md", "loop/state/FINDINGS.md",
        "loop/baseline/ci.tsv", "go.mod", "go.sum", "README.md",
    ]
    carved = ["docs/adr/accepted/001-vmm.md", "docs/adr/accepted/002-workspace-default.md"]  # ^docs/ matches them; lib.sh locks them all the same
    scratch = ["loop/private/body.json", "loop/private/987.log"]  # git ignores them, and PROMPT.md has the orchestrator write them
    allowlist = [line for line in read(os.path.join(root, "loop", "free-paths.txt")).split("\n") if line and not line.startswith("#")]
    edits = [r[5:-1] for r in settings["permissions"]["deny"] if r.startswith("Edit(")]
    odd = [rule for rule in edits if not re.match(r"^/[^/!][^\[\]!]*$", rule)]
    if odd:
        problems.append(f"this check models only Edit rules that start with one slash and hold no bracket or '!': {odd}")
    shapes = [(rule, edit_regex(rule)) for rule in edits if rule not in odd]
    for pattern in allowlist:
        if not any(re.search(pattern, name) for name in free):
            problems.append(f"free-paths.txt frees {pattern}, but the list of free paths in this check holds no example of it")
    for name in free:
        if not any(re.search(pattern, name) for pattern in allowlist):
            problems.append(f"this check calls {name} free, but free-paths.txt does not")
    for name in locked + carved:
        if name in locked and any(re.search(pattern, name) for pattern in allowlist):
            problems.append(f"this check calls {name} locked, but free-paths.txt frees it")
        if not any(shape.match(name) for _, shape in shapes):
            problems.append(f"the file tools must not touch this, and no Edit rule blocks it: {name}")
    for name in free + scratch:
        hit = [rule for rule, shape in shapes if shape.match(name)]
        if hit:
            problems.append(f"the loop must be able to write this, but it is blocked by {hit}: {name}")
    for rule, shape in shapes:
        if not any(shape.match(name) for name in locked + carved):
            problems.append(f"Edit({rule}) blocks nothing on the list of locked paths in this check; add an example")

    # 4. Models.
    if "availableModels" in settings:
        problems.append("availableModels is back; it blocks Claude Code's own safety fallback")
    if settings.get("fallbackModel") != ["claude-fable-5-1", "claude-opus-5-5"]:
        problems.append("fallbackModel is not Fable, then Opus")
    if "ANTHROPIC_DEFAULT_FABLE_MODEL" in settings.get("env", {}):
        problems.append("ANTHROPIC_DEFAULT_FABLE_MODEL is in the committed settings, where it binds everyone who opens the repository. "
                        "It belongs in the cloud environment (START-HERE.md step 5b) and on the command line in the second account")
    if settings.get("env", {}).get("CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH") != "1":
        problems.append("CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH is not 1, so subagents could start subagents")
    if settings.get("env", {}).get("LOOP_SETTINGS_LOADED") != "1" or 'echo "$LOOP_SETTINGS_LOADED"' not in prompt:
        problems.append("LOOP_SETTINGS_LOADED is not 1, or PROMPT.md section 0 no longer reads it to see that this file was loaded")
    if "model" in settings or settings["permissions"].get("allow") or "hooks" in settings:
        problems.append("the committed settings must hold no model choice, no allow rule and no hook")
    if settings.get("attribution", {}).get("sessionUrl") is not False:
        problems.append("attribution.sessionUrl must be false: the session link is a private URL")

    print(f"{len(rules)} Bash deny rules; {len(filled)} commands from PROMPT.md and {len(pasted)} from START-HERE.md allowed; "
          f"{len(never)} forbidden commands tried")
    print(f"{len(edits)} Edit deny rules; {len(locked) + len(carved)} locked paths and {len(free) + len(scratch)} paths the loop writes tried")
    if problems:
        print(f"FAIL: {len(problems)} problem(s)")
        for text in problems:
            print("  " + text)
        return 1
    print("PASS: the prompt's own commands run, the forbidden ones do not, the file tools reach what is free and nothing "
          "that is locked, and the model settings are as decided")
    return 0


if __name__ == "__main__":
    sys.exit(main())
