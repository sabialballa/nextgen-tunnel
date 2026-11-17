# Benchmark protocol

No invented performance numbers are used. Raw local results belong under `docs/evidence`; historical `deployment-records` are private and are not republished or treated as new measurements.

`scripts/local_lab.py` runs real server/client processes and echo backends on loopback. Each transport has alternating direct/tunnel ordering, repeated single TCP and four-connection TCP payload echo tests, paced UDP echo RTT samples and a primary-process outage test with a separately running TLS backup. It records binary hash, platform, counts, timeouts, P50/P95/P99 RTT and mean adjacent RTT difference. That last quantity is a clearly named RTT variability statistic, **not** RFC 3550 one-way interarrival jitter. UDP sequence mismatches are reported; a small loopback sample is not a robust wide-area reordering estimate.

TCP `echo_payload_mbit_s` counts payload in one direction; the link carries both request and echo. It is neither iperf bulk unidirectional throughput nor internet capacity. Multi-connection results are per-connection observations over approximately concurrent windows. UDP starts a fresh association, so its first sample includes setup; do not silently discard it. Process CPU time and RSS are sampled every 0.5 seconds on Windows/Linux, with CPU100%=one logical core; errors and raw samples are retained. Process peaks span all phases and must not be called per-throughput efficiency. Loopback UDP loss, zero or otherwise, says nothing about the Iranian route. No tuning is automatically applied from these results.

See [generated observed results](evidence/local-results.md) and [raw evidence](evidence/local-lab.json). Regenerate the table with `python3 scripts/summarize_lab.py docs/evidence/local-lab.json --output docs/evidence/local-results.md`.

The outage test terminates the actual primary process, waits for selected-path status to change, and verifies **new** TCP/UDP flows over backup. It restarts the primary, verifies recovery without unnecessary failback, then stops backup and verifies return to recovered primary. Existing sessions do not migrate. Optional `--soak-seconds` keeps a TCP flow open and runs paced TCP/UDP exchanges for a bounded interval. This is not a multi-hour leak test. Asymmetric loss, UDP blackholes, NAT rebinding and partial-path outages still need additional tests. Startup races or unmet prerequisites must be recorded as unverified, never successful.

## Controlled Linux/field matrix (pending)

For every candidate and a direct baseline: identical endpoints, time windows, versions, MTU, target rate, streams, packet sizes, duration and repetitions; alternate/randomize order and preserve raw logs. Record host kernel/CPU/NIC, virtualization steal time, route and background load. Use isolated test ports, operator-approved traffic ceilings and stop thresholds.

Measure iperf3 TCP upload/download and parallel streams; UDP upload/download at fixed rates and sizes; ping/fping RTT distributions and loss, mtr path, packet captures for reorder/size/timing, ss/nstat counters and sar process/system CPU/RSS. Run both directions and simultaneous load, with enough samples to estimate tails. Record connection setup latency separately, DNS behavior, IPv6 routing, certificate/auth failures and dependency scan output. UDP-over-TCP must have its own HOL/latency-under-loss evaluation.

Use Linux network namespaces or isolated VMs with `tc netem` for bandwidth, delay, loss, burst loss, reorder, outage and UDP filtering scenarios. Do not apply netem to an active production SSH interface. Clean Linux systemd installer tests on all target distributions, crash recovery, service restart, multi-hour memory trends and real Iranian DPI tests are still required.

BBR/CUBIC, socket buffers, offloads, GSO/GRO, MTU/MSS, queue disciplines, IRQ/CPU affinity and TFO are **not changed** by the Go installer. Compare before/after independently; retain a change only with measured benefit at the desired loss/RTT/CPU tradeoff. QUIC userspace congestion control is not controlled by Linux `tcp_congestion_control`.
