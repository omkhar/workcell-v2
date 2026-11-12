#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Omkhar Arasaratnam
#
# Installs the workcell binary: downloads SHA256SUMS and the binary for this host, checks the
# binary against SHA256SUMS, and only then installs it as $INSTALL_DIR/workcell. Usage: install.sh [tag]
# Nothing is installed if any step fails. UNTESTED against a real release until v2.0.0.
#
# The check catches damaged or swapped downloads. To check that SHA256SUMS was built by the release
# workflow, download SHA256SUMS and SHA256SUMS.sigstore.json from the release and run either:
#   cosign verify-blob --bundle SHA256SUMS.sigstore.json --certificate-oidc-issuer \
#     https://token.actions.githubusercontent.com --certificate-identity \
#     https://github.com/omkhar/workcell/.github/workflows/release.yml@refs/tags/<tag> SHA256SUMS
#   gh attestation verify <downloaded binary> --repo omkhar/workcell
#
# Environment: INSTALL_URL (where the files are; default the GitHub release of <tag>) and
# INSTALL_DIR (default $HOME/.local/bin).
set -eu

tag="${1:-v2.0.0}" # the maintainer bumps this with each release
url="${INSTALL_URL:-https://github.com/omkhar/workcell/releases/download/${tag}}"
dir="${INSTALL_DIR:-${HOME}/.local/bin}"
case "${dir}" in /*) ;; *) dir="$(pwd)/${dir}" ;; esac # absolute before the cd below
die() { echo "install: $*" >&2; exit 1; }

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) asset=workcell-linux-amd64 ;;
  Linux/aarch64 | Linux/arm64) asset=workcell-linux-arm64 ;;
  Darwin/arm64) asset=workcell-darwin-arm64 ;;
  *) die "unsupported system $(uname -s) $(uname -m): need Linux x86_64 or aarch64, or macOS arm64" ;;
esac
command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || die "need sha256sum or shasum"
check() { if command -v sha256sum >/dev/null 2>&1; then sha256sum -c "$1"; else shasum -a 256 -c "$1"; fi; }

new="${dir}/.workcell.new.$$"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}" "${new}"' EXIT
trap 'exit 1' HUP INT TERM
cd "${tmp}"

for f in SHA256SUMS "${asset}"; do
  curl -fsSL -o "${f}" "${url}/${f}" || die "cannot download ${url}/${f}"
done
grep "  ${asset}\$" SHA256SUMS > want || die "SHA256SUMS has no line for ${asset}"
check want >&2 || die "checksum of ${asset} does not match SHA256SUMS: nothing installed"

mkdir -p "${dir}"
cp "${asset}" "${new}"
chmod 0755 "${new}"
"${new}" --version || die "the downloaded ${asset} does not run: nothing installed"
mv -f "${new}" "${dir}/workcell"
echo "Installed ${dir}/workcell. Next: make sure ${dir} is on your PATH, then run: workcell doctor"
