#!/usr/bin/env bash
# Write one CycloneDX SBOM per release target and check each against its binary.
# Needs cyclonedx-gomod on PATH (the release workflow installs the pinned
# version; see docs/release.md) and the binaries scripts/release.sh left in
# OUTDIR/bin. Pins each SBOM's main component version to VERSION and rewrites
# SHA256SUMS to cover the SBOMs too.
#
# Usage: scripts/sbom.sh VERSION OUTDIR [os/arch ...]
set -euo pipefail

if [ $# -lt 2 ]; then
  echo "usage: scripts/sbom.sh VERSION OUTDIR [os/arch ...]" >&2
  exit 2
fi
version="$1"
out="$2"
shift 2
if [ $# -eq 0 ]; then
  set -- linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
fi
command -v cyclonedx-gomod >/dev/null 2>&1 || { echo "sbom: cyclonedx-gomod is not on PATH" >&2; exit 2; }

cd "$(dirname "$0")/.."
root="$(pwd)"
out="$(cd "$out" && pwd)"

for target in "$@"; do
  os="${target%/*}"
  arch="${target#*/}"
  file="$out/augur_${version}_${os}_${arch}.sbom.cdx.json"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" cyclonedx-gomod app -json -noserial -notimestamp -std \
    -output-version 1.6 -main ./cmd/augur -output "$file" .
  # cyclonedx-gomod stamps the main component's version from the VCS state: the
  # tag on a tagged checkout, a pseudo-version on any other commit. Pin it to
  # VERSION, so a dry run on a commit and the tag run on that commit write the
  # same bytes (and the same SHA256SUMS). Plain text replacement, no re-encoding.
  python3 -I - "$file" "$version" <<'PY'
import json, sys
path, version = sys.argv[1], sys.argv[2]
text = open(path, encoding="utf-8").read()
cur = json.loads(text)["metadata"]["component"].get("version", "")
if not cur.startswith("v"):
    sys.exit("sbom: the main component has no version to pin: %r" % cur)
if cur != version:
    text = text.replace(cur, version)
    json.loads(text)  # still valid JSON
    open(path, "w", encoding="utf-8").write(text)
PY
  "$root/scripts/sbom-check.sh" "$out/bin/${os}_${arch}/augur" "$file"
  echo "sbom: $(basename "$file")"
done

"$root/scripts/sums.sh" "$out"
