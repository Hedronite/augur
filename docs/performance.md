# Performance

Measured budgets for Augur, on the development host named below. The rule
from the release review: **measure first** — a budget that passes gets no
optimization work, and only a failing budget earns changes, with before and
after numbers recorded here.

## Budgets

| Budget | Limit |
| --- | --- |
| One poll at 4000 alerts (decode + evaluate + render + write) | < 250 ms CPU |
| `serve` steady-state RSS at 4000 alerts | < 64 MiB |
| No leak | heap after poll 1000 within 10% of heap after poll 100 (post-GC `HeapAlloc`), goroutines flat |

The 4000-alert figure is the `serve` input cap; 100 000 is the `evaluate`
cap. `evaluate` on a 16 MiB input is rejected above the cap, so the budgets
bound every supported input.

Advisory: `serve` decodes a body *before* it applies the 4000-alert cap, so a
16 MiB body holding more than 4000 alerts allocates roughly 149 MB
transiently — the measured 16 MiB decode working set — before it is refused
as `too_many`. That peak is bounded and fails closed, but the 64 MiB RSS
budget describes steady state at 4000 alerts, not that transient peak.

## Benchmarks

Go benchmarks report ns/op, B/op and allocs/op (`b.ReportAllocs()`), run on
the machine named in the table with `-count=5` and a sensible `-benchtime`.
The alert mixes are deterministic and built in the benchmarks; no fixture
files are read.

| Benchmark | What it measures |
| --- | --- |
| `BenchmarkEvaluate9` / `4000` / `100000` | the engine at today's real alert count, the `serve` cap, and the `evaluate` cap |
| `BenchmarkDecodeAM16MiB` | the decoder at the 16 MiB body cap |
| `BenchmarkJSONLargest` | canonical JSON of the largest supported verdict (4000 alerts, bounded-field worst case) |

| Measurement | Value | Result |
| --- | --- | --- |
| `serve` one poll at 4000 alerts (decode + evaluate + render + write, real binary) | about 72 ms CPU per poll (3.45 s CPU over 48 polls, startup included); wall per poll from the `poll` log line: min 54 ms, median 75 ms, max 93 ms, loopback fetch and fsync'd write included | pass (< 250 ms), no optimization |
| `serve` steady-state RSS at 4000 alerts | 35,824 KiB (35.0 MiB), flat from the first minute to the last sample | pass (< 64 MiB) |
| No leak (`TestSoak`: 1000 polls at 4000 alerts, injected clock, real atomic writer) | heap 1,951,256 B after poll 100, 2,081,032 B after poll 1000 (+6.6%, window is 10%); goroutines 4 → 4 | pass |

CPU: Apple M4 Max (`machdep.cpu.brand_string`), Go 1.27.4 (`go version` on the build host), release-style build
(`go build -trimpath`). Method: the real `augur serve --interval 5s` polling a
local static Alertmanager stub over loopback returning 4000 alerts (one
Watchdog plus 3999 distinct name-and-host alerts over five hosts, a mix of
active, suppressed and unprocessed); verdict file 1,308,491 bytes; RSS from
`ps -o rss`, CPU from `ps -o cputime` (whole process, startup included).

## Reproducing

On the build host:

```sh
go test -run '^$' -bench . -benchmem -count=5 ./internal/engine ./internal/decode ./internal/render
```

`DecodeAM`'s benchmark reads a synthetic 16 MiB payload built in the test;
the `serve` poll and RSS numbers come from `TestSoak`
(`internal/serve/soak_test.go`, also available as `make soak`; it skips under
`-race` and runs as a CI step in every matrix cell) and the real-binary run:
build with `go build -trimpath -o augur ./cmd/augur`, serve a 4000-alert
response from any static loopback HTTP server at `/api/v2/alerts`, run
`augur serve --interval 5s` for a few minutes, and read `ps -o rss,cputime`.

### Go benchmarks

Every row is the **median of five runs** (`-benchtime=1s -count=5 -benchmem`,
`b.ReportAllocs()` everywhere). Run-to-run variance is real on a shared
development host — individual runs of the same benchmark differ by up to
**1.7x** (worst case `BenchmarkDecodeAM4000`: 24.1 ms to 73.7 ms) — so plan
from the medians, not the fastest run, and the budget decision is made on
medians.

| Benchmark | Input | ns/op (median) | Range | B/op | allocs/op |
| --- | --- | --- | --- | --- | --- |
| `BenchmarkEvaluate9` | 9 alerts | 5.2 µs | 5.15–5.66 µs | 5 347 | 46 |
| `BenchmarkEvaluate4000` | 4 000 alerts | 1.85 ms | 1.84–1.95 ms | 2 546 469 | 190 |
| `BenchmarkEvaluate100000` | 100 000 alerts | 55.2 ms | 54.3–60.1 ms | 95 302 913 | 303 |
| `BenchmarkDecodeAM16MiB` | 16 MiB, ~40 000 alerts | 222 ms | 212–356 ms | 149 136 726 | 2 999 834 |
| `BenchmarkDecodeAM16MiBDense` | 9.6 MB, 100 000 minimal alerts | 177 ms | 176–245 ms | 217 804 260 | 3 000 081 |
| `BenchmarkDecodeAM4000` | 4 000 alerts, 1.8 MB | 25.4 ms | 24.1–73.7 ms | 15 932 037 | 323 842 |
| `BenchmarkJSONLargest` | 4 000-alert worst case | 4.50 ms | 4.44–8.57 ms | 6 568 077 | 8 014 |

Notes:

- Engine allocation **count** does not grow with alert count: the engine
  allocates per merged group, not per alert.
- The 16 MiB decode rate (75 MB/s) is lower than the A2 measurement because
  the decoder now type-checks every property the input schema declares. That
  is the cost of the contract, not a regression to chase.
- The widest supported verdict renders at 868 B/alert, 3.31 MiB for 4 000
  alerts — under Vigil's 4 MiB read cap, corroborating the poll run's
  1,308,491-byte verdict for the realistic mix.

### Budget check at the `serve` cap

Sum of the measured parts at 4 000 alerts: decode 25.4 ms + `Evaluate`
1.85 ms + `render.JSON` 4.50 ms ≈ **32 ms known** against the 250 ms CPU
budget — a 7x margin before the write and loop that the real-binary poll run
(above, ~72 ms CPU) covers. All budgets pass; per the release rule no
optimisation was done, and the three benchmark files are measurement only.

## Live (production instance)

*To be filled after the v0.1.1 install: live RSS and poll time measured on
the running instance, appended by PM through the frontend seat. This section
is intentionally empty until then.*
