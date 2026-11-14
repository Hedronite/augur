#!/usr/bin/env bash
# Write one CycloneDX SBOM per release target and check each against its binary.
# Needs cyclonedx-gomod on PATH (the release workflow installs the pinned
# version; see docs/release.md) and the binaries scripts/release.sh left in
# OUTDIR/bin. Makes each SBOM host-independent, gives it a deterministic
# serialNumber and checks the attestation action will accept it
# (scripts/sbomtool.py), and rewrites SHA256SUMS to cover the SBOMs too.
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
  # Make the tool's output host-independent and give it its deterministic
  # serialNumber (see scripts/sbomtool.py), then check what the attestation
  # action will check: it refuses a CycloneDX file without a serialNumber.
  python3 -I "$root/scripts/sbomtool.py" normalize "$file" "$version"
  python3 -I "$root/scripts/sbomtool.py" accept "$file"
  "$root/scripts/sbom-check.sh" "$out/bin/${os}_${arch}/augur" "$file"
  echo "sbom: $(basename "$file")"
done

"$root/scripts/sums.sh" "$out"
