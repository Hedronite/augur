<!--
Thank you for contributing to Augur. Pull requests land only through the
checklist below; fixes go in as new commits, never a force-push.
-->

## What does this change?

One behaviour or one contract change per pull request. If it shifts the
contract, the schemas and the docs change in the same PR.

## Checklist

- [ ] Every commit is signed off (`git commit -s`; DCO).
- [ ] `make gate` is green locally (vet, lint, tests with `-race`,
      govulncheck, conformance, scrub).
- [ ] No hostnames, IP addresses, seat or person names in code, fixtures,
      docs, commits, or this PR text — synthetic slugs (`host-a` … `host-e`)
      only.
- [ ] If the contract changed: `schema/` and `docs/` updated together, and
      the fixtures stay untouched (fixtures are the spec).
- [ ] Tests cover the behaviour: table-driven for rules, a failing branch for
      fail-closed paths, no test that only pins plumbing.
