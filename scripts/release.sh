#!/usr/bin/env bash
# Build the release tarballs and SHA256SUMS. The output depends only on the
# commit, the version string and the Go toolchain, so two builds on different
# machines and paths give the same bytes.
#
# Usage: scripts/release.sh VERSION OUTDIR [os/arch ...]
#   VERSION  the tag as written, for example v0.1.1
#   OUTDIR   created if missing; receives augur_<VERSION>_<os>_<arch>.tar.gz,
#            SHA256SUMS, and bin/<os>_<arch>/augur (the unpacked binaries)
#   targets  default: linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
#
# SOURCE_DATE_EPOCH (seconds) sets every file time in the archives; it defaults
# to the commit time of HEAD, and the script stops if it has neither (a source
# archive with no .git): a silent fallback would change the bytes. The flags below are the ones `make build` uses.
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "usage: scripts/release.sh VERSION OUTDIR [os/arch ...]" >&2
  exit 2
fi
version="$1"
out="$2"
shift 2
if [ $# -eq 0 ]; then
  set -- linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
fi

if ! printf '%s' "$version" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$'; then
  echo "release: VERSION '$version' is not a tag like v0.1.1" >&2
  exit 2
fi

cd "$(dirname "$0")/.."
root="$(pwd)"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

epoch="${SOURCE_DATE_EPOCH:-}"
if [ -z "$epoch" ]; then
  epoch="$(git log -1 --format=%ct 2>/dev/null || true)"
fi
if [ -z "$epoch" ]; then
  echo "release: SOURCE_DATE_EPOCH is not set and there is no git history to take the commit time from." >&2
  echo "release: set SOURCE_DATE_EPOCH to the tagged commit's time in seconds, or build from a git checkout." >&2
  exit 2
fi
if ! printf '%s' "$epoch" | grep -Eq '^[0-9]+$'; then
  echo "release: SOURCE_DATE_EPOCH '$epoch' is not a number of seconds" >&2
  exit 2
fi

tools="$(mktemp -d)"
trap 'rm -rf "$tools"' EXIT
go build -o "$tools/mkarchive" ./scripts/mkarchive

echo "release: $version, go $(go env GOVERSION), epoch $epoch"
for target in "$@"; do
  os="${target%/*}"
  arch="${target#*/}"
  if [ "$os" = "$target" ] || [ -z "$os" ] || [ -z "$arch" ]; then
    echo "release: target '$target' is not os/arch" >&2
    exit 2
  fi
  name="augur_${version}_${os}_${arch}"
  bindir="$out/bin/${os}_${arch}"
  mkdir -p "$bindir"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false \
    -ldflags "-s -w -buildid= -X github.com/Hedronite/augur/internal/cli.version=${version}" \
    -o "$bindir/augur" ./cmd/augur
  "$tools/mkarchive" "$out/$name.tar.gz" "$name" "$epoch" \
    "augur=$bindir/augur" \
    "LICENSE-APACHE=$root/LICENSE-APACHE" \
    "LICENSE-MIT=$root/LICENSE-MIT" \
    "README.md=$root/README.md" \
    "deploy/augur.service=$root/deploy/augur.service" \
    "schema=$root/schema" \
    "examples=$root/examples"
  echo "release: $name.tar.gz"
done

"$root/scripts/sums.sh" "$out"
