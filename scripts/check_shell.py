#!/usr/bin/env python3
"""Parse installer and rendered legacy shell with Bash, without executing them."""
import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import agent
from model import role_plan

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--shell", default="bash")
    a = p.parse_args()
    version = subprocess.run([a.shell, "--version"], capture_output=True, text=True, check=True).stdout
    if "GNU bash" not in version:
        raise ValueError("rendered legacy scripts require GNU Bash for syntax validation")
    count = 0
    for path in (ROOT / "scripts").glob("*.sh"):
        subprocess.run([a.shell, "-n"], input=path.read_text(), text=True, check=True, capture_output=True)
        count += 1
    config = json.loads((ROOT / "deployment.example.json").read_text())
    key = base64.b64encode(bytes(32)).decode()
    for role in ("entry", "exit"):
        plan = role_plan(config, role, {"entry": key, "exit": key}, "ab" * 32,
                         {"tcp": [48320], "udp": [500, 4500, 1701, 46954, 34569]})
        for text in agent.render(plan, key).values():
            if text.startswith("#!/bin/bash"):
                subprocess.run([a.shell, "-n"], input=text, text=True, check=True, capture_output=True)
                count += 1
    print(json.dumps({"shell": version.splitlines()[0], "scripts_parsed": count, "scripts_executed": 0}))

if __name__ == "__main__": main()
