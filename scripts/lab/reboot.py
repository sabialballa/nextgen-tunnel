#!/usr/bin/env python3
"""Verify real guest reboot, changed boot ID, systemd and authenticated paths."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import time
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from scripts.lab.vm import ssh_args
def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--name',default='debian12');a=p.parse_args();ssh=ssh_args(a.name)
    before=subprocess.check_output(ssh+['cat /proc/sys/kernel/random/boot_id'],text=True).strip()
    subprocess.run(ssh+['sudo systemctl reboot'],capture_output=True,timeout=15)
    start=time.monotonic();report=dict(before_boot_id=before,verified=False)
    try:
        while time.monotonic()-start<180:
            time.sleep(3)
            try:
                r=subprocess.run(ssh+['cat /proc/sys/kernel/random/boot_id; systemctl is-active nextgen-tunnel nextgen-lab-echo; sudo /home/lab/project/bin/nextgen-tunnel probe -config /var/lib/nextgen-lab/client.json'],capture_output=True,text=True,timeout=15)
                lines=r.stdout.splitlines()
                if r.returncode==0 and lines and lines[0]!=before and lines[1:3]==['active','active'] and r.stdout.count('healthy=true')==2:
                    report.update(verified=True,after_boot_id=lines[0],elapsed_seconds=time.monotonic()-start,stdout=r.stdout);break
            except subprocess.TimeoutExpired:pass
        if not report['verified']:raise RuntimeError('guest reboot acceptance deadline exceeded')
    finally:
        a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2))
    print(json.dumps(report))
if __name__=='__main__':main()
