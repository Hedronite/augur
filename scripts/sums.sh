#!/usr/bin/env bash
# Write OUTDIR/SHA256SUMS over the release tarballs and SBOMs in OUTDIR: sorted
# by file name, the two-space format that `sha256sum -c` reads.
# Usage: scripts/sums.sh OUTDIR
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: scripts/sums.sh OUTDIR" >&2
  exit 2
fi
cd "$1"

if command -v sha256sum >/dev/null 2>&1; then
  hash() { sha256sum "$@"; }
else
  hash() { shasum -a 256 "$@"; }
fi

files="$(LC_ALL=C ls augur_*.tar.gz augur_*.sbom.cdx.json 2>/dev/null | LC_ALL=C sort || true)"
if [ -z "$files" ]; then
  echo "sums: no release files in $1" >&2
  exit 1
fi
# shellcheck disable=SC2086 # the names are plain file names without spaces
hash $files > SHA256SUMS
echo "sums: $(wc -l < SHA256SUMS | tr -d ' ') files in SHA256SUMS"
