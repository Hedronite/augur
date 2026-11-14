# Augur's fields in `vigil.summary/v0`

Vigil combines authority verdicts into one summary. Augur is an authority: its
verdict document is read from a file (never executed), and two things land in
the summary — one entry in `verdicts[]`, and the `augur{}` block. This page is
the mapping between them. The contracts are
[`schema/verdict.v0.json`](../schema/verdict.v0.json) (what Augur publishes) and
[`schema/vigil-block.v0.json`](../schema/vigil-block.v0.json) (what Vigil
copies into `augur{}`).

Vigil vendors the block schema and the mapping goldens byte for byte at a
pinned commit, so the goldens under `testdata/vigil/` are the executable form
of this page: when this page and a golden disagree, the golden wins and this
page is fixed.

## What Vigil reads and computes

- Vigil reads Augur's verdict file with a 4 MiB cap and ignores unknown
  fields. Freshness is the age of `generated_at`; past `stale_after`
  (default 120 s) the verdict is `stale`.
- Vigil never runs Augur and never derives severity from raw data. It only
  combines what authorities publish, plus its own two caps.

## Mapping: verdict → `verdicts[]` entry

| Verdict field | `verdicts[]` entry |
| --- | --- |
| — (constant) | `source: "augur"` |
| `sources[]` health, or the file's age | `state`: `ok`, `stale` (aged past `stale_after`), or `unavailable` (unreadable, undecodable, unknown major) |
| `overall` | `severity` (null when `unavailable`) |
| `reasons[]` (top-level rollup) | `reasons[]`, passed through unchanged |
| `generated_at` | `observed_at` |

Vigil may add its own codes to `reasons[]` and may cap `severity` (below).
Nothing else about the entry is Vigil's to change.

## Mapping: verdict → `augur{}` block

The block is a **bounded projection** of the verdict, not a mirror. The
verdict file remains the complete source of truth; the block exists so a
reader of the summary can see the actionable detail without reading the whole
verdict.

| Block field | Contents |
| --- | --- |
| `apiVersion` | const `augur.vigil-block/v0` |
| `generated_at` | the verdict's `generated_at`, Z-only timestamp |
| `policy_sha256` | the verdict's `policy_sha256` |
| `watchdog` | `{seen, last_seen}` from the verdict |
| `alertmanager_last_ok` | the verdict's `sources[0].last_ok` (null when never ok) |
| `counts` | exact partition over **all** verdict alerts (below) |
| `alerts` | raising alerts only, at most 50 (below) |
| `omitted` | raising alerts not listed |

### The count partition

`counts` is computed over every alert in the verdict and always partitions
`total`:

```
total = counts.raising.RED + counts.raising.YELLOW + counts.expected + counts.suppressed
```

An alert is:

- `expected` when `expected` is `true` (the heartbeat, or a matched hold);
- else `suppressed` when its status is `suppressed` (silenced or inhibited);
- else `raising`, counted under its severity (`RED` or `YELLOW`).

The counts are never filtered or capped: even when the alert list is
truncated, the partition stays exact, so a reader never loses the shape of
the alert set. GREEN is not a count column: an alert is either expected or
suppressible or raising, and a raising alert is never GREEN.

### The alert list: filter, sort, cap

- **Filter:** raising alerts only (the partition above). The heartbeat and
  held alerts are what the counts already express; listing them would spend
  the budget on noise.
- **Sort:** severity first (RED before YELLOW), then `starts_at` ascending,
  then `host`, then `name` — deterministic, independent of input order.
- **Cap:** 50 items. Anything beyond the cap is counted in `omitted`:
  `omitted = raising.RED + raising.YELLOW - len(alerts)`.
- **Why truncation is safe here** when our own file never truncates: the file
  is the source of truth, and in the file a dropped alert could hide the only
  RED. In the block the severity truth already lives in `verdicts[].severity`
  and in the exact `counts`; `omitted` names exactly how many raising alerts
  were left in the source, and the sort guarantees the listed ones are the
  most severe and oldest first. Nothing is hidden — it is summarized, with
  the pointer back to the file.

`augur{}` is data only: it never changes `overall`, the exit code, or any
other authority's verdict. Per-host alert state never joins `hosts[]`; that
array stays Simplex's.

## What Vigil adds itself

Vigil contributes its own reason codes to `verdicts[].reasons` and applies
one cap. These are Vigil's, not Augur's:

- **Codes:** `source_stale` (the verdict file aged past `stale_after`),
  `source_unavailable` and `authority_unavailable` (the authority could not
  be read), `schema_major` (the authority document is on an unknown major),
  and `clock_skew` (the file's modified time is ahead of its own
  `generated_at`).
- **The stale cap:** a stale verdict counts as at least YELLOW — GREEN rises
  to YELLOW, YELLOW and RED stay. The entry keeps the severity Augur
  published and gains `source_stale`; `overall` carries the capped value.
- **The missing-authority cap:** while Augur is `unavailable`, `overall`
  cannot be better than YELLOW.

Augur's reason codes never collide with these: the 2026-11-14 renames moved
our source codes off Vigil's names — see the rename table in
[`docs/reasons.md`](reasons.md).

## Version rule

- The verdict document carries `apiVersion: augur.verdict/v0`; the block
  carries `apiVersion: augur.vigil-block/v0`. Vigil refuses a document on an
  unknown major: Augur then counts as `unavailable` with reason
  `authority_unavailable` and `detail_code` `schema_major`, and the caps
  apply.
- Inside a major the change rule is additive only. A field may be added to
  the block; it is never removed, renamed, re-typed or given a new meaning
  without a new major.

## Why Augur's `sources[]` never enters the block

Vigil's `sources[]` is the single place status lives: its schema says status
belongs there "and nowhere else", and Vigil already surfaces Augur there as
the `augur` source (state, `observed_at`, `last_ok`, `detail_code`). Duplicating
our per-source state in the block would create two places that can disagree,
so the ruling is: **the block carries no source state.** The one exception is
`alertmanager_last_ok`, a timestamp and not a status, which answers "how
fresh was the alert set" without duplicating any state field.

## Worked examples

Both examples are copied byte for byte from the mapping goldens under
`testdata/vigil/`; the transform is exercised by `FuzzVigilMap`, and the
goldens regenerate with `go test ./internal/vigilmap -update` — never by hand.

### A YELLOW split (`two-replicas-split`)

A verdict with a Watchdog heartbeat and one `NodeExporterDown` on `host-a`
whose declared replica is live and silent: YELLOW
`node_exporter_views_split`. The `verdicts[]` entry carries no reasons beyond
the rollup: the verdict's top-level reasons report heartbeat and source
state, and this verdict has nothing to report there — the cause of the YELLOW
lives on the alert, inside the block.

`verdicts[]` entry:

```json
{
  "source": "augur",
  "state": "ok",
  "severity": "YELLOW",
  "reasons": [],
  "observed_at": "2026-01-15T12:00:00Z"
}

```

`augur{}` block:

```json
{
  "apiVersion": "augur.vigil-block/v0",
  "generated_at": "2026-01-15T12:00:00Z",
  "policy_sha256": "242dd46ee0f6f82db53e12c64eb4c7145ccfaf7ca4f2c36ba3d52bf8caae9b0c",
  "watchdog": {
    "seen": true,
    "last_seen": "2026-01-15T11:58:00Z"
  },
  "alertmanager_last_ok": "2026-01-15T12:00:00Z",
  "counts": {
    "total": 2,
    "raising": {
      "RED": 0,
      "YELLOW": 1
    },
    "expected": 1,
    "suppressed": 0
  },
  "alerts": [
    {
      "name": "NodeExporterDown",
      "host": "host-a",
      "severity": "YELLOW",
      "starts_at": "2026-01-15T11:45:00Z",
      "rule_id": "node-exporter-down",
      "replicas": [
        "r1"
      ],
      "reasons": [
        "node_exporter_views_split",
        "rule_matched"
      ]
    }
  ],
  "omitted": 0
}

```

### Blind and unreachable (`blind-unreachable`)

Alertmanager has been unreachable: no alerts at all, the heartbeat unseen,
and `alertmanager_last_ok` (`11:54:00Z`, six minutes before `generated_at`)
showing how long the source has been silent. The verdict is RED
`observability_blind` with `watchdog_missing` and
`alertmanager_unreachable` on the entry. The file itself was readable and
current, so Vigil's entry state is still `ok`: Vigil judges the file's age,
Augur judges the alert source. Nothing is truncated (`omitted` is 0): an
empty raising set is the truthful block.

`verdicts[]` entry:

```json
{
  "source": "augur",
  "state": "ok",
  "severity": "RED",
  "reasons": [
    "alertmanager_unreachable",
    "observability_blind",
    "watchdog_missing"
  ],
  "observed_at": "2026-01-15T12:00:00Z"
}

```

`augur{}` block:

```json
{
  "apiVersion": "augur.vigil-block/v0",
  "generated_at": "2026-01-15T12:00:00Z",
  "policy_sha256": "4b72105466aa2f84e399336c5e31f5052fd5e0911f2662c31fed79df4fdb57f0",
  "watchdog": {
    "seen": false,
    "last_seen": null
  },
  "alertmanager_last_ok": "2026-01-15T11:54:00Z",
  "counts": {
    "total": 0,
    "raising": {
      "RED": 0,
      "YELLOW": 0
    },
    "expected": 0,
    "suppressed": 0
  },
  "alerts": [],
  "omitted": 0
}

```
