# Security

This repository is Workcell v2 **under construction**. It never publishes a release, a tag or a download, and nothing
here is meant to be installed or relied on yet. If you see a release here, do not use it, and please report it. The
released product, and its security policy, live at <https://github.com/omkhar/workcell>.

## Reporting

Do not disclose a sandbox escape, a credential leak or a signing bypass in a public issue.
Report it privately through GitHub's private vulnerability reporting on
[omkhar/workcell](https://github.com/omkhar/workcell/security/advisories/new), whether it concerns v1 or the code here.
If that channel is unavailable, contact the repository owner privately through GitHub first.

## How changes are signed here

A coding-agent loop writes most commits in this repository. They reach `main` as squash merges, which GitHub signs.
They are not signed by the maintainer.

The maintainer's own GPG key signs three things: every change to a locked file (anything outside
`loop/free-paths.txt`), every human gate in the plan, and the checkpoints named `loop-checkpoint-N`.

- `main` holds GitHub's squash of each pull request. So the maintainer's signature is not on `main` itself. It is on the last
  commit of the pull request, `refs/pull/N/head`, which has the same files.
- A checkpoint is a signed tag object. It means that the maintainer has looked through the changes since the checkpoint
  before it. GitHub holds no tags for this repository, so the checkpoints are kept under another name. Import
  `.github/maintainer.asc` and compare its fingerprint with the one below. Then fetch and check the checkpoints:
  `git fetch --no-tags origin 'refs/checkpoints/loop-checkpoint-*:refs/tags/loop-checkpoint-*'`,
  then `git verify-tag loop-checkpoint-0`.

The key's fingerprint is:

```
9055 4248 C4F7 CC08 6BB7  45D0 DA5A 8E9F 536C 42FD
```

`loop/REFERENCE.md` section 9 says what this arrangement protects against, and what it does not.
