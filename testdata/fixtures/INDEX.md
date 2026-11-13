# Fixture index

One directory per rule: `alerts.json` (the exact bytes handed to `evaluate`), `policy.yaml`, `now.txt` (also the `--now` value) and either `expected.json` (a full verdict document) or `expected_error.json`. Every fixture is self-contained; nothing is shared. Times are UTC and `now.txt` is the same instant everywhere so fixtures compare.

Every `expected.json` pins `policy_sha256` to the sha256 of that directory's `policy.yaml` bytes, so editing a fixture policy means regenerating its digest.

## Conventions these fixtures pin

The spec fixes the outcome; these are the details the spec leaves open, frozen here so A1 has one target.

1. `evaluate` reports a single source: `{"id":"file","state":"ok","last_ok":<now>,"alert_count":<len(alerts.json)>}`.
2. Top-level `reasons[]` carries heartbeat and source conditions only (`watchdog_only`, `watchdog_missing`, `observability_blind`, `source_unreachable`, `source_stale`). When alerts alone drive the severity, it is empty; `alerts[].reasons[]` explains the rest.
3. Any alert named by `watchdog.alertname` sets `watchdog.seen`, with `last_seen` equal to that alert's `updatedAt`. An empty array means not seen.
4. The Watchdog appears in `alerts[]` with severity `GREEN`, `expected: true`, `rule_id: null` and reason `heartbeat` (plus `silenced` when suppressed). It never takes `unmatched_default`.
5. `rule_matched` accompanies every alert a rule matched, including held and suppressed ones. `rule_id` names the rule that decided the final severity, which is the worst one when several match. `rule_id` is `null` exactly when `unmatched_default` is present.
6. Holds and suppression are decided before the `node_exporter_red_hold` escalation, so neither can produce a `node_exporter_*` RED reason (`24`, `31`). Suppression also outranks escalation.
7. `expected: true` means "excused right now": the Watchdog and alerts under an active hold. An announced dark past `expires_at` is `expected: false` and raises (`23`).
8. `severity` is Augur's classified severity; `source_severity` is the alert's own `severity` label or `null`. `status` is `active` or `suppressed`.
9. `overall` is the worst severity among alerts that are neither expected nor suppressed, floored at `YELLOW` when the heartbeat is missing (`12`).
10. Alerts that share `(name, host)` across replica labels merge into one entry: `replicas[]` is the sorted distinct set of views that reported, `starts_at` is the **latest** reporting start (the moment every reporting view agreed, so age stays truthful), and severity is the worst (`51`, `52`).
11. `host` is `labels[host_label]`, falling back to `labels.instance`. A value failing `^[a-z0-9-]{1,32}$` becomes `unmapped` with reason `unmapped_host`, and an unmapped host is never first-class, so it never escalates (`61`).
12. Age is `now - startsAt`, clamped at 0; a negative age adds `clock_skew` (`62`). For a merged alert the age is measured from the merged `starts_at`, so the hold reasons follow the latest reporting start: `node_exporter_within_hold` only appears while that merged age is inside `node_exporter_red_hold` (`52`).
13. `alerts[]` sorts by `(host, name, starts_at)`; `reasons[]` and `replicas[]` sort ascending.
14. Unknown alert fields are ignored (`64`); a reversed input order yields a byte-identical document (`65`).
15. For `expected_error.json`, `exit` and `code` are the contract (`3` input, `4` policy). `detail` is a hint. Every exit-4 fixture also declares `policy_schema`: `invalid` when the policy must fail `policy.v0.json` on its own, `valid` when only the engine can reject it (`79`, a regex that does not compile). `76` expects both offending field paths because `validate` reports every error, not just the first.
16. `replicas:` declares the views whose alerts reach the source; unset means one unlabeled view. A declared replica absent from the input is **live and silent**, which splits the views (`54`), unless an active `PeerPrometheusDown`/`Absent` names it through `replica_label`, which makes it **lost** and lets a single past-hold report stand as RED (`55`).
17. Output bounds. The verdict schema is not run at runtime, so the decoder must enforce the same limits itself: `name` must match `^[A-Za-z_][A-Za-z0-9_:]{0,127}$`, otherwise it is reported as `unnamed`; `source_severity` must match `^[a-z][a-z0-9_]{0,31}$`, otherwise it is `null`; each `replicas[]` value must match `^[a-z0-9-]{1,32}$`, otherwise `unmapped`; `rule_id` is a policy id, already bounded by the policy schema. No other input string reaches the output.

## Fixtures

| Fixture | Domain | §5 / contract rule | Expected |
| --- | --- | --- | --- |

| `10-watchdog-only` | evaluate | Watchdog seen, nothing else firing | GREEN — watchdog_only |
| `11-watchdog-missing` | evaluate | Heartbeat not seen; same alert set as 42 apart from the Watchdog | YELLOW — watchdog_missing |
| `12-empty-array` | evaluate | Empty array counts as Heartbeat not seen | YELLOW — watchdog_missing |
| `13-silenced-watchdog` | evaluate | A silenced Watchdog is still a heartbeat | GREEN — watchdog_only |
| `20-expected-dark-port` | evaluate | expected_dark hold never raises overall | GREEN — watchdog_only |
| `21-known-hold-18080` | evaluate | known_hold never raises overall | GREEN — watchdog_only |
| `22-announced-dark-active` | evaluate | announced_dark before expires_at does not raise | GREEN — watchdog_only |
| `23-announced-dark-expired` | evaluate | announced_dark after expires_at raises YELLOW | YELLOW — (alerts raise) |
| `24-held-node-exporter-past-hold` | evaluate | A held first-class host never escalates to RED | GREEN — watchdog_only |
| `30-silenced-alert` | evaluate | A silenced alert does not raise overall | GREEN — watchdog_only |
| `31-inhibited-alert` | evaluate | An inhibited alert does not raise overall, and suppression is applied before escalation | GREEN — watchdog_only |
| `40-peer-prom-down` | evaluate | PeerPrometheusDown is YELLOW | YELLOW — (alerts raise) |
| `41-peer-prom-absent` | evaluate | PeerPrometheusAbsent is YELLOW | YELLOW — (alerts raise) |
| `42-node-exporter-before-hold` | evaluate | NodeExporterDown before node_exporter_red_hold is YELLOW; A/B pair with 11 | YELLOW — (alerts raise) |
| `43-ssh-failure` | evaluate | An unexpected SSH failure is YELLOW | YELLOW — (alerts raise) |
| `44-disk-warn-build-box` | evaluate | Disk warn on a build box is YELLOW | YELLOW — (alerts raise) |
| `45-disk-crit-build-box` | evaluate | Disk crit on a build box is YELLOW, never RED | YELLOW — (alerts raise) |
| `46-orb-dark-not-yellow` | evaluate | A peer absence that is expected dark is not YELLOW | GREEN — watchdog_only |
| `50-node-exporter-past-hold-single-view` | evaluate | First-class NodeExporterDown past the hold, one view, is RED | RED — (alerts raise) |
| `51-node-exporter-two-replicas-agree` | evaluate | Two views that agree past the hold are RED | RED — (alerts raise) |
| `52-node-exporter-two-replicas-disagree` | evaluate | Two views that disagree are not RED; the merged age is the latest reporting start | YELLOW — (alerts raise) |
| `53-worst-rule-wins` | evaluate | Every matching rule applies; worst severity wins and rule_id names the deciding rule | RED — (alerts raise) |
| `60-unmatched-alert` | evaluate | An unmatched alert takes the fail-closed default; source_severity is preserved | YELLOW — (alerts raise) |
| `61-unmapped-host` | evaluate | A host label that fails the slug pattern is reported unmapped and never escalates | YELLOW — (alerts raise) |
| `62-clock-skew` | evaluate | startsAt in the future clamps age to zero and reports clock_skew | YELLOW — (alerts raise) |
| `63-instance-fallback` | evaluate | With no host label, instance supplies the host and still reaches the first-class escalation | RED — (alerts raise) |
| `64-unknown-fields-ignored` | evaluate | Unknown alert fields are ignored, so an Alertmanager upgrade does not change the verdict | YELLOW — (alerts raise) |
| `65-order-invariance` | evaluate | Reversing the input order gives a byte-identical document (same alerts and policy as 51) | RED — (alerts raise) |
| `70-reject-webhook-v4` | evaluate | Alertmanager webhook v4 payload is rejected with a typed error | exit 3 unsupported_payload |
| `71-reject-grafana` | evaluate | Grafana contact-point payload is rejected with a typed error | exit 3 unsupported_payload |
| `72-reject-malformed-json` | evaluate | Truncated JSON is an input error, never a verdict | exit 3 invalid_input |
| `73-reject-shape` | evaluate | Overall shape mismatch: an alert with no status | exit 3 invalid_input |
| `74-policy-green-default` | evaluate | A GREEN default is rejected | exit 4 invalid_policy |
| `75-policy-unknown-key` | evaluate | Unknown policy keys are errors | exit 4 invalid_policy |
| `76-policy-reports-all` | validate | validate reports every policy error, not just the first | exit 4 invalid_policy |
| `77-policy-bad-duration` | validate | A duration outside the accepted grammar is an error naming the field | exit 4 invalid_policy |
| `54-node-exporter-declared-replica-silent` | evaluate | A declared replica that is live and silent splits the views | YELLOW — (alerts raise) |
| `55-node-exporter-declared-replica-lost` | evaluate | A declared replica that is lost does not block RED | RED — (alerts raise) |
| `66-default-red-unmatched` | evaluate | A RED default classifies an unmatched alert as RED | RED — (alerts raise) |
| `67-unprocessed-treated-active` | evaluate | An unprocessed alert counts like an active one, so it raises | YELLOW — (alerts raise) |
| `78-policy-unknown-rule-key` | evaluate | An unknown key nested in a rule is an error | exit 4 invalid_policy |
| `79-policy-bad-regex` | validate | A matcher regex that does not compile is a policy error; the schema cannot see it, so validate must compile it | exit 4 invalid_policy |

## Coverage against §5

| §5 statement | Fixtures |
| --- | --- |
| Watchdog seen, nothing else firing | `10` |
| Watchdog not seen | `11`, `12` |
| Empty array counts as not seen | `12` |
| A silenced Watchdog is still a heartbeat | `13` |
| `expected_dark` / `known_hold` never raise | `20`, `21`, `46` |
| `announced_dark` before / after `expires_at` | `22`, `23` |
| Silenced and inhibited do not raise | `30`, `31` |
| `PeerPrometheusDown` / `Absent` are YELLOW | `40`, `41` |
| NodeExporterDown before the hold | `42` |
| NodeExporterDown past the hold, one view | `50` |
| Two replicas must agree | `51`, `52` |
| A held first-class host never escalates | `24` |
| SSH failure | `43` |
| Disk warn / crit on a build box | `44`, `45` |
| Unmatched alert takes the default | `60` |
| Host slug pattern, else `unmapped` | `61` |
| `instance` fallback | `63` |
| Hold age, clamp and `clock_skew` | `62`, plus every hold fixture |
| Worst matching rule wins | `53` |
| RED default applies to an unmatched alert | `66` |
| `unprocessed` is classified like `active` | `67` |
| Every declared replica reports past the merged hold | `51` |
| Merged age within the hold | `52` |
| A declared replica is live and silent | `54` |
| A declared replica is lost and does not block RED | `55` |
| Unknown key nested in a rule | `78` |
| A matcher regex that does not compile | `79` |
| Unknown fields ignored | `64` |
| Determinism under reordering | `65` |
| Reject webhook v4 / Grafana | `70`, `71` |
| Malformed JSON / shape mismatch | `72`, `73` |
| Invalid policy: default, key, duration, all errors | `74`–`77` |

Not covered by a fixture, by nature: `observability_blind` (needs `serve` state, so it belongs to A2), and the properties "the engine reads no clock", "no unvalidated input string in the output" and "order never changes the verdict" beyond `65` — those belong to `FuzzEvaluate` and the scrub test in A1.
