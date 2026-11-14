# Operating `augur serve`

`augur serve` is a poll loop: it reads the Alertmanager v2 API on a loopback
address, classifies the current alert state, and keeps one verdict file
current. It writes; it never talks back — no silencing, acking, routing, and
no HTTP listener of its own. This page is the operational contract: what the
file promises, what the source states mean, and what the process does across
restarts.

## The command

```sh
augur serve \
  --policy /etc/augur/policy.yaml \
  --alertmanager http://127.0.0.1:9093 \
  --out /var/lib/augur/verdict.json \
  [--interval 30s]
```

| Flag | Meaning |
| --- | --- |
| `--policy FILE` | The `augur.policy/v0` policy. Read once at startup; there is no reload in v0 — restart to apply a new policy. The real policy lives off-repo, mode 0640. |
| `--alertmanager URL` | `http://` to a **literal** loopback address: `127.0.0.0/8` or `[::1]`. `localhost` and other names are refused: resolving a name is a trust step Augur does not need. The polled path is `GET /api/v2/alerts?active=true&silenced=true&inhibited=true&unprocessed=true`, sent explicitly. |
| `--out FILE` | The verdict file. Its directory must exist and be writable; startup probes it with a temp file. |
| `--interval` | Poll interval, 5 s to 60 s, default 30 s. The bounds keep the file fresh inside Vigil's 120 s `stale_after`. |

Requests follow no redirects, use no proxy (proxy environment variables are
ignored), carry a per-request timeout of `min(10s, interval/2)`, and cap the
response body at 16 MiB.

## Startup

- The first verdict is written **straight away**, not after one interval. The
  dead-man clock starts when the process starts.
- Startup refusals exit **5** with a house-style message and write nothing:
  a non-loopback URL, an unreadable policy, an unwritable output directory,
  or an interval out of bounds.
- A policy that is readable but invalid exits **4** (same as `validate`).
- Stale temp files from a crashed run (`.augur-*.tmp` in the output
  directory) are removed at startup, matching only that exact prefix.

## The file contract

The verdict file is the interface Vigil reads. It holds one canonical
`augur.verdict/v0` document (see [`schema/verdict.v0.json`](../schema/verdict.v0.json)).

- Written atomically: temp file in the same directory, write, `fsync`,
  `rename`, then `fsync` of the directory. A reader always sees either the
  previous complete file or the new complete file — never a partial one.
- Mode 0644.
- Under Vigil's 4 MiB read cap. A verdict that would not fit is an internal
  error (exit 6): `alerts[]` is never truncated to fit, because a partial
  verdict could hide a RED. The last good file is left in place and ages
  stale (below).

## What every poll produces

Every poll writes a verdict — including a failed poll. A snapshot from a
failed poll is never silently replaced by older alerts: classifying old
alerts as current would fail open.

| Source state | What happened | Verdict effect |
| --- | --- | --- |
| `ok` | Poll succeeded; the snapshot is decoded and classified normally. | Per the watch rules; Watchdog seen → GREEN-eligible. |
| `unreachable` | Connect error, timeout, non-200, refused redirect, over-cap body, or decode error. Classified as an empty snapshot: `alerts: []`. | YELLOW `alertmanager_unreachable` + `watchdog_missing`; RED `observability_blind` once `deadman_window` has passed since the last good heartbeat. |
| `stale` | Poll succeeded, but the Watchdog's `updatedAt` is older than `deadman_window`: Alertmanager is up while the alert source stopped refreshing. The Watchdog counts as **not seen**. | `alertmanager_stale` added; the tracker proceeds as for a missed heartbeat → YELLOW, then RED past the window. `alert_count` still counts every alert read, including the dropped Watchdog. |

## The dead-man window

- The window is the policy's `watchdog.deadman_window` (5 m in the example).
- Not seen (or unreachable or stale) for less than the window → YELLOW
  `watchdog_missing`; for the window or longer → RED `observability_blind`.
- A Watchdog seen again recovers straight away.
- A clock that appears to run backwards never moves the state back: it is
  treated as zero elapsed time and recorded as `evaluation_clock_backwards`.
- There is no state file. A restart resets the dead-man clock: after a
  restart, the process treats the startup instant as the last observation,
  so a restart can briefly hold a verdict at YELLOW that would have been
  RED. This is a documented limitation (SPEC §10).

## Lifecycle

| Event | Behaviour | Exit |
| --- | --- | --- |
| Startup refusal | Nothing written; house-style error. | 5 |
| Readable but invalid policy | Nothing written. | 4 |
| Panic | Recovered; last file untouched. | 6 |
| `SIGTERM` / `SIGINT` | The write in progress finishes, then the process exits. | 0 |
| `SIGHUP` | Logged and ignored; there is no policy reload in v0. Restart to reload. | — |
| Verdict over 4 MiB | Internal error; last file left in place to age stale. | 6 |

After a panic (exit 6) or any other non-zero exit, `Restart=on-failure` in the
example unit restarts the process, bounded by systemd's start limits
(`StartLimitIntervalSec` and `StartLimitBurst`); a restart resets the dead-man
clock. A clean `SIGTERM` exit 0 is not restarted.

When `serve` stops with no new write — crash, panic, or clean shutdown — the
last file is left alone. Vigil ages a file that has not been updated for
120 s (`stale_after`) into `stale` on its side; nothing needs to delete it.

## Logs

`log/slog` JSON on stderr:

- one line per poll: `overall`, `alert_count`, `source_state`, `duration_ms`;
- one line per tracker state change;
- errors log their typed kind, not the raw body.

Logs carry enum values and counts only — never label values, alert text, or
URLs with credentials. Illustrative shape:

```json
{"time":"2026-01-15T12:00:05Z","level":"INFO","msg":"poll","overall":"GREEN","alert_count":2,"source_state":"ok","duration_ms":12}
```

## Deployment

`deploy/augur.service` in the repository is an example systemd unit — **not
installed** — with generic paths (`/etc/augur/policy.yaml`,
`/var/lib/augur/verdict.json`), a dedicated user, and a hardened sandbox.
Adjust it to the host before use; installing anywhere is a separate,
explicitly approved step.
