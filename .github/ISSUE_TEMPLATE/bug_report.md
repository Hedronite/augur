---
name: Bug report
about: Something Augur did that it should not have
labels: bug
---

A bug is a wrong verdict, a wrong exit code, a crash, or a misleading error.
If you found a security problem, do **not** open an issue — use private
vulnerability reporting (see [SECURITY.md](../SECURITY.md)).

**What happened?**

A clear description. If a verdict was wrong, include the output (human or
`--json`).

**What did you expect?**

The verdict, exit code, or behaviour you expected.

**How to reproduce?**

Minimal input that shows it. **Scrub the input first**: no IP addresses,
hostnames, tailnet names, or secrets — use the synthetic slugs `host-a`
through `host-e`.

**Environment**

- `augur version` output:
- platform (os/arch) and how you installed Augur:
