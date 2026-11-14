#!/usr/bin/env python3
"""Normalise and check the CycloneDX SBOMs the release publishes.

  sbomtool.py normalize FILE VERSION   make FILE host-independent and give it a serialNumber
  sbomtool.py accept FILE...           the attestation action's acceptance rule, plus our serial rule
  sbomtool.py selftest                 the rule rejects what it should

Run it as `python3 -I scripts/sbomtool.py ...`. Standard library only.

normalize drops what depends on where cyclonedx-gomod ran or on the VCS state:
  - metadata.tools[].hashes: the digests of the cyclonedx-gomod binary that
    ran, which differ per build platform (the tool name and version stay);
  - the main module's version, which the tool stamps from the VCS state (the
    tag on a tagged checkout, a pseudo-version on any other commit): pinned to
    VERSION in metadata.component (version, purl, bom-ref) and in the
    dependency-graph entry for that bom-ref, and nowhere else. It fails if the
    old version is still anywhere in the file afterwards.
It then adds the serialNumber. The tool is run with -noserial so that its output
is reproducible, but actions/attest accepts a CycloneDX document only when
bomFormat, specVersion and serialNumber are all present (src/sbom.ts at the
pinned v4.2.2). A random serial would break reproducibility, so the serial is
derived from the content: urn:uuid: plus a UUIDv5 over the sha256 of the file
exactly as written below, without the serialNumber key. Anyone can recompute
it (accept does).
"""
import hashlib
import json
import os
import re
import sys
import tempfile
import uuid

# The namespace of every serial: fixed, derived from the project URL.
NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/Hedronite/augur")
MAX_SIZE = 16 * 1024 * 1024  # the action refuses an SBOM larger than this
SERIAL_RE = re.compile(r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def canonical(doc):
    """The bytes of an SBOM as the release writes it (no serialNumber when hashing)."""
    return (json.dumps(doc, indent=2) + "\n").encode("utf-8")


def serial_for(doc):
    body = {k: v for k, v in doc.items() if k != "serialNumber"}
    digest = hashlib.sha256(canonical(body)).hexdigest()
    return "urn:uuid:" + str(uuid.uuid5(NAMESPACE, digest))


def with_serial(doc):
    """doc with serialNumber placed right after specVersion, where CycloneDX puts it."""
    serial = serial_for(doc)
    out = {}
    for k, v in doc.items():
        if k == "serialNumber":
            continue
        out[k] = v
        if k == "specVersion":
            out["serialNumber"] = serial
    if "serialNumber" not in out:
        sys.exit("sbomtool: no specVersion in the SBOM")
    return out


def normalize(path, version):
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

    doc = with_serial(doc)
    with open(path, "wb") as f:
        f.write(canonical(doc))


def problems(path):
    """Why the attestation action, or our own serial rule, would refuse this SBOM."""
    bad = []
    size = os.path.getsize(path)
    if size > MAX_SIZE:
        bad.append("larger than %d bytes" % MAX_SIZE)
    with open(path, "rb") as f:
        raw = f.read()
    try:
        doc = json.loads(raw)
    except ValueError as e:
        return ["not JSON: %s" % e]
    if not isinstance(doc, dict):
        return ["not a JSON object"]
    # actions/attest src/sbom.ts checkIsCycloneDX, at the pinned version.
    for key in ("bomFormat", "serialNumber", "specVersion"):
        if not doc.get(key):
            bad.append("%s is missing or empty (actions/attest refuses it as 'Unsupported SBOM format')" % key)
    if doc.get("bomFormat") not in (None, "CycloneDX"):
        bad.append("bomFormat is %r, not CycloneDX" % doc.get("bomFormat"))
    # Ours: the serial is the derived one, and the file is in the canonical form.
    serial = doc.get("serialNumber")
    if serial:
        if not SERIAL_RE.match(serial):
            bad.append("serialNumber %r is not urn:uuid: plus a UUIDv5" % serial)
        elif serial != serial_for(doc):
            bad.append("serialNumber %s is not the one derived from the content (%s)" % (serial, serial_for(doc)))
        if raw != canonical(doc):
            bad.append("the file is not in the canonical form the serial is derived from")
    return bad


def accept(paths):
    failed = False
    for p in paths:
        bad = problems(p)
        if bad:
            failed = True
            for b in bad:
                print("sbom-accept: %s: %s" % (os.path.basename(p), b), file=sys.stderr)
        else:
            print("sbom-accept: %s: ok" % os.path.basename(p))
    if failed:
        sys.exit(1)


def selftest():
    base = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "metadata": {"component": {"name": "x"}}}
    with tempfile.TemporaryDirectory() as d:
        def write(name, doc, raw=None):
            p = os.path.join(d, name)
            with open(p, "wb") as f:
                f.write(raw if raw is not None else canonical(doc))
            return p

        good = with_serial(base)
        assert not problems(write("good.json", good)), problems(write("good.json", good))
        assert serial_for(good) == good["serialNumber"], "the serial is derived from the content"
        assert with_serial(good) == good, "adding a serial twice changes nothing"

        cases = {
            "no serial (the v0.1.0 failure)": write("a.json", base),
            "no bomFormat": write("b.json", {k: v for k, v in good.items() if k != "bomFormat"}),
            "no specVersion": write("c.json", {k: v for k, v in good.items() if k != "specVersion"}),
            "random serial": write("d.json", dict(good, serialNumber="urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79")),
            "serial of another content": write("e.json", dict(good, version=2)),
            "not canonical": write("f.json", good, raw=json.dumps(good).encode()),
            "not JSON": write("g.json", None, raw=b"{"),
            "empty serial": write("h.json", dict(good, serialNumber="")),
        }
        for name, p in cases.items():
            if not problems(p):
                sys.exit("selftest: an SBOM with %s was accepted" % name)
    print("sbomtool selftest: ok (accepts a good SBOM, rejects %d bad ones)" % len(cases))


def main(argv):
    if len(argv) == 4 and argv[1] == "normalize":
        normalize(argv[2], argv[3])
    elif len(argv) >= 3 and argv[1] == "accept":
        accept(argv[2:])
    elif len(argv) == 2 and argv[1] == "selftest":
        selftest()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
