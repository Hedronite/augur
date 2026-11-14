# Contributing

Thanks for looking at Augur. This document covers the workflow, the commit rules, and the house style for errors and tests.

## Ground rules

- Augur only inspects and advises. It never silences, acknowledges, routes or notifies. Keep it that way.
- Fail closed. Unknown input, an invalid policy, or an ambiguous classification is an error — never a GREEN verdict.
- No secrets, IP addresses, hostnames, or real infrastructure names in code, fixtures, docs, commits or PR text. Host slugs in examples and fixtures are synthetic (`host-a` … `host-e`); alert rule names are public. If you find real data in the repository, treat it as a security issue and report it (see [SECURITY.md](SECURITY.md)).
- Build and test on development machines, never on production or alerting hosts.

## Getting started

- A current Go toolchain (stable and the previous release are both supported).
- `go vet`, `golangci-lint` and `govulncheck` must be clean; tests run under the race detector.
- `make gate` runs the full local gate. Run it before opening a PR.

## Workflow

1. Fork or branch; `main` is protected — every change lands through a pull request, and force-pushes are rejected. Fixes go in as new commits, never a force-push.
2. Keep pull requests focused: one behaviour or one contract change each.
3. Update docs and schemas together with code. [`schema/verdict.v0.json`](schema/verdict.v0.json), the policy schema, and the reason-code enum in [`docs/reasons.md`](docs/reasons.md) are the contract; a code change that shifts the contract without a schema change is a bug.

## Commits and the DCO

Sign off every commit — this certifies your contribution under the [Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s
```

Each commit must carry a `Signed-off-by` line matching its author. Commits and PR text must not contain hostnames or personal identifiers.

## Error-message house style

Every user-facing error follows the same shape:

1. **Name the file and the field.** `policy.yaml: holds[1].expires_at: …`
2. **Show a short excerpt of the offending input** — one line, no more. Excerpts are hard-bounded: truncated, stripped of control characters, and never the raw unbounded value.
3. **Say how to fix it.** Not just what broke; what valid looks like.

Additional rules:

- Errors go to stderr. stdout carries only the verdict or the document.
- `validate` reports *every* policy error, not just the first — a user should not have to fix one error per run.
- Never echo raw label values, secrets or full payloads into an error message. Excerpts are truncated and control-character-free by construction (`internal/render`); every producer must feed it bounded values too.
- Unsupported input is a *typed* error naming the detected shape, so callers can distinguish an Alertmanager webhook message from a Grafana contact-point payload without parsing the message themselves.

## Repository hygiene

`scripts/scrub.sh` checks every tracked file for addresses, tailnet names and home paths, and fails the build on a hit, reporting only `file:line`. Run it locally before opening a PR:

```sh
scripts/scrub.sh               # check the tree
scripts/scrub.sh --self-test   # verify the patterns catch their samples
```

To check a private denylist, set `AUGUR_SCRUB_EXTRA` to newline-separated extended regexes (or to a file of them). The list is never printed, committed or echoed; a hit is still reported as `file:line` only. When the variable is empty, the extra step is skipped and the script says so.

## Tests

- Table-driven tests for every classification rule and every fail-closed branch. A rule that is not in the table is not a rule.
- Fuzz the decoders, the payload sniffer, the policy parser and the engine.
- The properties that matter: determinism (byte-identical output), insensitivity to alert order, Watchdog and held alerts never raise `overall`, exempt alerts never RED, and no unvalidated input string ever appears in the output.
- Schema conformance: golden outputs and the example policy validate against the hand-written schemas.

## Vendored Vigil contract

The block schema and the mapping goldens under `testdata/vigil/` are vendored into Vigil byte for byte at a pinned commit. When Vigil's side of the contract changes, refresh the vendored files (`testdata/vigil/vendor/`, whose `SOURCE` file names the pinned commit), update the goldens together with [`docs/vigil.md`](docs/vigil.md), and land the refresh as its own commit so the pin is reviewable.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT), at your option. Unless you explicitly state otherwise, any contribution you intentionally submit for inclusion in this work, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
