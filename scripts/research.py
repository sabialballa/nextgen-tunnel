#!/usr/bin/env python3
"""Capture public upstream maintenance evidence; never infer performance from it."""
import argparse
import concurrent.futures
import datetime
import json
from pathlib import Path
import urllib.request
import urllib.error

REPOS = {
    "hysteria2": "apernet/hysteria", "tuic": "tuic-protocol/tuic",
    "wireguard-go": "WireGuard/wireguard-go", "amneziawg": "amnezia-vpn/amneziawg-go",
    "quic-go": "quic-go/quic-go", "masque": "quic-go/masque-go",
    "xray": "XTLS/Xray-core", "anytls": "anytls/anytls-go",
    "trojan": "trojan-gfw/trojan", "phantun": "dndx/phantun",
    "udp2raw": "wangyu-/udp2raw",
}

def fetch(repo, resource):
    url = "https://api.github.com/repos/" + repo + resource
    request = urllib.request.Request(url, headers={"User-Agent": "nextgen-tunnel-research", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return {"url": url, "data": json.load(response)}
    except (OSError, urllib.error.URLError, ValueError) as exc:
        return {"url": url, "error": str(exc)}

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    output = {"captured_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "method": "unauthenticated primary GitHub API; errors are evidence gaps", "upstreams": {}}
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        jobs = {pool.submit(fetch, repo, resource): (name, label)
                for name, repo in REPOS.items()
                for label, resource in (("metadata", ""), ("release", "/releases/latest"),
                                        ("recent_issues", "/issues?state=open&per_page=3"),
                                        ("source_head", "/commits?per_page=1"))}
        for job in concurrent.futures.as_completed(jobs):
            name, label = jobs[job]
            output["upstreams"].setdefault(name, {})[label] = job.result()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2), encoding="utf-8")
    failures = sum("error" in item for repo in output["upstreams"].values() for item in repo.values())
    print(json.dumps({"upstreams": len(REPOS), "failed_requests": failures, "output": str(args.output)}))

if __name__ == "__main__":
    main()
