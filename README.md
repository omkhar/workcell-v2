# Workcell v2 (under construction)

A local sandbox for coding agents: one short-lived microVM per session, nothing in the guest trusted, network and
credentials enforced on the host.

**This is not ready to use.** The released product is at <https://github.com/omkhar/workcell>.

v2 is being built here by a coding-agent loop, one small piece at a time, under rules the loop cannot change. This
repository is a building site. When v2 is finished, the maintainer will propose it as version 2 of `omkhar/workcell`, and
archive this repository.

| To see | Read |
|--------|------|
| What v2 must be | `loop/SPEC.md` |
| What is done and what is next | `loop/state/PLAN.md` |
| How the loop is run and kept in check | `loop/START-HERE.md`, `loop/REFERENCE.md` |

Pull requests, issues and comments from outside are switched off while the loop runs.

**This repository never publishes a release, a tag or a download.** If you see one here, do not use it. Please report it
(`SECURITY.md`).

## If you open this repository in Claude Code

`.claude/settings.json` and `.claude/agents/` are made for the loop, and Claude Code applies them to anyone who works in a clone.

- If your model is overloaded, the fallback chain here replaces yours. It starts with Fable 5.1, which costs more than Opus,
  Sonnet or Haiku.
- Eight agents are defined here: `architect`, `auditor`, `builder`, `redteam`, `reviewer`, `scout`, `scribe` and `verifier`. Five of
  them run on the top tier. They take the place of agents of yours that have the same names.
- The rest only forbids or leaves out. There is a list of commands and paths that Claude is told to leave alone. Agents may
  not start agents of their own. Commits made from the cloud carry no link to the session. One variable,
  `LOOP_SETTINGS_LOADED`, only shows the loop that these settings were loaded.

To use your own fallback chain, set `fallbackModel` in `.claude/settings.local.json`, which git ignores here.
