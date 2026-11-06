# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Omkhar Arasaratnam
#
# Installs the release binaries (brew tap omkhar/workcell https://github.com/omkhar/workcell).
# UNTESTED until v2.0.0: the first release fills every sha256 below from its SHA256SUMS.
class Workcell < Formula
  desc "Local sandbox for coding agents: one short-lived microVM per session"
  homepage "https://github.com/omkhar/workcell"
  version "2.0.0"
  license "Apache-2.0"

  on_macos do
    depends_on arch: :arm64
    url "https://github.com/omkhar/workcell/releases/download/v#{version}/workcell-darwin-arm64"
    sha256 "0000000000000000000000000000000000000000000000000000000000000000" # workcell-darwin-arm64
  end

  on_linux do
    on_intel do
      url "https://github.com/omkhar/workcell/releases/download/v#{version}/workcell-linux-amd64"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # workcell-linux-amd64
    end
    on_arm do
      url "https://github.com/omkhar/workcell/releases/download/v#{version}/workcell-linux-arm64"
      sha256 "0000000000000000000000000000000000000000000000000000000000000000" # workcell-linux-arm64
    end
  end

  def install
    bin.install Dir["workcell-*"].fetch(0) => "workcell" # the one downloaded file
  end

  test do
    assert_match "workcell", shell_output("#{bin}/workcell --version")
  end
end
