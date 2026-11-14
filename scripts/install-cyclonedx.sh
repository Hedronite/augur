#!/usr/bin/env bash
# Install cyclonedx-gomod at the pinned version, after checking that the module
# the Go proxy serves has the pinned checksum. The one place the pin lives:
# release.yml and the repro job in ci.yml both call this.
#
# Usage: scripts/install-cyclonedx.sh BINDIR     (BINDIR receives cyclonedx-gomod)
set -euo pipefail

version="v1.12.0"
sum="h1:OuFUYNhnjpju7RNArOVPPchFPWNobGfhrHODDPKcgZs="
mod="github.com/CycloneDX/cyclonedx-gomod"

if [ $# -ne 1 ]; then
  echo "usage: scripts/install-cyclonedx.sh BINDIR" >&2
  exit 2
fi
bindir="$1"
mkdir -p "$bindir"
bindir="$(cd "$bindir" && pwd)"

# Outside any module, so nothing in the checkout is read or changed.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
got="$(cd "$tmp" && go mod download -json "$mod@$version" | sed -n 's/.*"Sum": "\(.*\)",$/\1/p')"
if [ "$got" != "$sum" ]; then
  echo "install-cyclonedx: $mod@$version has module sum '$got', expected '$sum'" >&2
  exit 1
fi
(cd "$tmp" && GOBIN="$bindir" go install "$mod/cmd/cyclonedx-gomod@$version")
echo "install-cyclonedx: $mod $version in $bindir"
