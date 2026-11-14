#!/usr/bin/env bash
# Write one CycloneDX SBOM per release target and check each against its binary.
# Needs cyclonedx-gomod on PATH (the release workflow installs the pinned
# version; see docs/release.md) and the binaries scripts/release.sh left in
# OUTDIR/bin. Makes each SBOM host-independent (see below) and rewrites
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
  # Normalise the two things in the tool's output that depend on where it ran,
  # so the same commit gives the same SBOM bytes on any host:
  #  - metadata.tools[].hashes: the digests of the cyclonedx-gomod binary that
  #    ran (it differs per build platform); the tool name and version stay.
  #  - the main module's version, which the tool stamps from the VCS state (the
  #    tag on a tagged checkout, a pseudo-version on any other commit): pinned
  #    to VERSION in metadata.component (version, purl, bom-ref) and in the
  #    dependency graph entry for that bom-ref, and nowhere else. The script
  #    fails if the old version is still anywhere in the file afterwards.
  python3 -I - "$file" "$version" <<'PY'
import json, sys
path, version = sys.argv[1], sys.argv[2]
with open(path, encoding="utf-8") as f:
    doc = json.load(f)

tools = doc["metadata"]["tools"]
if isinstance(tools, dict):  # CycloneDX 1.5+ may nest them under "components"
    tools = tools.get("components", []) + tools.get("services", [])
for tool in tools:
    tool.pop("hashes", None)

comp = doc["metadata"]["component"]
old = comp.get("version", "")
if not old.startswith("v"):
    sys.exit("sbom: the main component has no version to pin: %r" % old)
if old != version:
    old_ref = comp["bom-ref"]
    comp["version"] = version
    comp["purl"] = comp["purl"].replace("@" + old, "@" + version, 1)
    comp["bom-ref"] = old_ref.replace("@" + old, "@" + version, 1)
    for dep in doc.get("dependencies", []):
        if dep["ref"] == old_ref:
            dep["ref"] = comp["bom-ref"]
        if "dependsOn" in dep:  # never add a key the tool did not write
            dep["dependsOn"] = [comp["bom-ref"] if x == old_ref else x for x in dep["dependsOn"]]
    if old in json.dumps(doc):
        sys.exit("sbom: the old main version %r is still in the SBOM after pinning" % old)

with open(path, "w", encoding="utf-8") as f:
    json.dump(doc, f, indent=2)
    f.write("\n")
PY
  "$root/scripts/sbom-check.sh" "$out/bin/${os}_${arch}/augur" "$file"
  echo "sbom: $(basename "$file")"
done

"$root/scripts/sums.sh" "$out"
