#!/usr/bin/env python3
"""Generate a traceable table from an actual local_lab JSON report."""
import argparse
import collections
import json
from pathlib import Path
import statistics

def main():
    p = argparse.ArgumentParser()
    p.add_argument("input", type=Path)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args(); report = json.loads(a.input.read_text())
    groups = collections.defaultdict(list)
    for row in report["results"]:
        label = row["transport"] if row["transport"] != "direct" else "direct (paired with " + row["paired_with"] + ")"
        groups[label].append(row)
    lines = ["# Observed loopback laboratory results", "", "Generated from `" + a.input.name + "`; measured at " + report["finished_at"] + ".",
             "", "Binary SHA256: `" + report["binary_sha256"] + "`.", "", "Scope: " + report["scope"] + ". Iran DPI: **Not Verified**.",
             "", "Each table value is a median across repetitions unless shown as a packet total. TCP is application echo payload throughput, not internet throughput. UDP P95 is the median of per-run P95 values, not a pooled percentile.",
             "", "| Path | Runs | TCP single Mbps | TCP 4-flow sum Mbps | UDP received/sent | Median run P95 RTT ms |", "|---|---:|---:|---:|---:|---:|"]
    for label, rows in groups.items():
        single = statistics.median(r["tcp_single"]["echo_payload_mbit_s"] for r in rows)
        multi = statistics.median(sum(x["echo_payload_mbit_s"] for x in r["tcp_four_connections"]) for r in rows)
        received = sum(r["udp"]["received"] for r in rows); sent = sum(r["udp"]["sent"] for r in rows)
        tails = [r["udp"]["rtt_p95_ms"] for r in rows if r["udp"]["rtt_p95_ms"] is not None]
        tail = f"{statistics.median(tails):.3f}" if tails else "N/A"
        lines.append(f"| {label} | {len(rows)} | {single:.2f} | {multi:.2f} | {received}/{sent} | {tail} |")
    lines += ["", "Resource samples are process CPU time and RSS every 0.5 seconds; CPU100%=one logical core. The following peaks span the entire lab, including warm-up, probes and all test phases; they are not per-throughput efficiency measurements.",
              "", "| Process | Observed peak RSS MiB | Observed peak sampled CPU % of one core |", "|---|---:|---:|"]
    resources = collections.defaultdict(list)
    for sample in report.get("resource_samples", []):
        for name, value in sample["processes"].items(): resources[name].append(value)
    for name, values in resources.items():
        rss = max(v["rss_bytes"] for v in values) / 1024**2
        cpu = max((v.get("cpu_percent_one_core", 0) for v in values), default=0)
        lines.append(f"| {name} | {rss:.2f} | {cpu:.2f} |")
    failover = report.get("failover", {})
    lines += ["", "Failover verified: **" + str(failover.get("verified", False)) + "**."]
    if failover.get("verified"):
        lines.append(f"Observed path-change detection after primary termination: {failover['detection_seconds']:.3f} seconds. New TCP succeeded; new UDP received {failover['udp_after_outage']['received']}/{failover['udp_after_outage']['sent']}. Existing sessions did not migrate.")
    recovery = report.get("recovery", {})
    if recovery:
        lines += ["", "Primary restarted and recovered: " + str(recovery.get("primary_recovered")) + "; healthy backup retained: " + str(recovery.get("healthy_backup_retained")) + ".",
                  f"After backup termination, return to recovered primary took {recovery['return_after_backup_outage_seconds']:.3f} seconds; TCP and UDP were rechecked."]
    soak = report.get("stability", {})
    if soak:
        lines += ["", f"Bounded stability run: {soak['elapsed_seconds']:.3f} seconds with {soak['tcp_exchanges']} successful exchanges over one TCP session; UDP {soak['udp_received']}/{soak['udp_sent']}, timeouts {soak['udp_timeouts']}. This does not establish multi-hour stability or absence of memory leaks."]
    lines += ["", "Harness errors: " + json.dumps(report.get("errors", [])) + ". Resource sampling errors: " + json.dumps(report.get("resource_sampling_errors", [])) + ".",
              "", "No Linux installation, wide-area loss/jitter claim, DPI validation, tuning recommendation or production capacity conclusion follows from this loopback run."]
    a.output.write_text("\n".join(lines) + "\n", encoding="utf-8")

if __name__ == "__main__": main()
