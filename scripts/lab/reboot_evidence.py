#!/usr/bin/env python3
"""Read-only recovery evidence after an explicitly requested owned-stack reboot."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    p=argparse.ArgumentParser();p.add_argument('--peer4',required=True);p.add_argument('--peer6',required=True);a=p.parse_args()
    stage=Path('/opt/nextgen-stack-stage');work=stage/'hour-rc2'
    if os.geteuid()!=0 or not Path('/var/lib/nextgen-stack-installer/ownership.json').exists():p.error('owned root stack required')
    before=(work/'boot-before.txt').read_text().strip();now=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    issued=json.loads((work/'reboot-issued.json').read_text())
    assert before==issued['boot_before'] and before!=now,'fresh reboot not established'
    result=subprocess.run(['python3',str(stage/'stack_snapshot_final.py'),'--directory',str(stage),'--output',str(work/'reboot-snapshot.json'),'--peer4',a.peer4,'--peer6',a.peer6,'--after-cleanup'],capture_output=True,text=True,timeout=90)
    r=json.loads((work/'reboot-snapshot.json').read_text())
    r.update(before_boot_id=before,after_boot_id=now,fresh_boot_changed=before!=now,reboot_issued_wall_time=issued['issued_wall_time'],observed_wall_time=time.time(),observation_elapsed_seconds=time.time()-issued['issued_wall_time'],permanent_services_manually_started=False)
    # elapsed is the observation bound, not an exact measured outage duration.
    r['success']=r['success'] and result.returncode==0 and r['fresh_boot_changed']
    out=work/'reboot-evidence.json';out.write_text(json.dumps(r,indent=2)+'\n');out.chmod(0o600)
    print(json.dumps(dict(success=r['success'],fresh_boot_changed=r['fresh_boot_changed'],observation_elapsed_seconds=r['observation_elapsed_seconds'])))
    raise SystemExit(0 if r['success'] else 1)


if __name__=='__main__':main()
