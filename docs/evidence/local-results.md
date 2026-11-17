# Observed loopback laboratory results

Generated from `local-lab.json`; measured at 2026-11-16T13:08:36.535490+00:00.

Binary SHA256: `65c51a48aa298ce9ca0df541e1ce57dc8d3d0690bd478e767070fade51c55295`.

Scope: loopback only; payload echo throughput counts one direction; actual network carries request and response. Iran DPI: **Not Verified**.

Each table value is a median across repetitions unless shown as a packet total. TCP is application echo payload throughput, not internet throughput. UDP P95 is the median of per-run P95 values, not a pooled percentile.

| Path | Runs | TCP single Mbps | TCP 4-flow sum Mbps | UDP received/sent | Median run P95 RTT ms |
|---|---:|---:|---:|---:|---:|
| direct (paired with tls) | 3 | 2739.03 | 3917.75 | 300/300 | 0.508 |
| tls | 3 | 735.54 | 1573.00 | 300/300 | 1.694 |
| direct (paired with quic) | 3 | 2611.27 | 3474.30 | 300/300 | 0.467 |
| quic | 3 | 51.95 | 299.30 | 300/300 | 1.706 |

Resource samples are process CPU time and RSS every 0.5 seconds; CPU100%=one logical core. The following peaks span the entire lab, including warm-up, probes and all test phases; they are not per-throughput efficiency measurements.

| Process | Observed peak RSS MiB | Observed peak sampled CPU % of one core |
|---|---:|---:|
| server | 19.27 | 393.75 |
| backup | 16.65 | 63.71 |
| tls | 17.20 | 227.55 |
| quic | 19.63 | 408.79 |
| failover | 19.07 | 143.75 |
| restarted-primary | 18.79 | 159.38 |

Failover verified: **True**.
Observed path-change detection after primary termination: 21.891 seconds. New TCP succeeded; new UDP received 20/20. Existing sessions did not migrate.

Primary restarted and recovered: True; healthy backup retained: True.
After backup termination, return to recovered primary took 7.047 seconds; TCP and UDP were rechecked.

Bounded stability run: 120.093 seconds with 1184 successful exchanges over one TCP session; UDP 1184/1184, timeouts 0. This does not establish multi-hour stability or absence of memory leaks.

Harness errors: []. Resource sampling errors: [].

No Linux installation, wide-area loss/jitter claim, DPI validation, tuning recommendation or production capacity conclusion follows from this loopback run.
