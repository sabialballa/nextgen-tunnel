#!/usr/bin/env python3
"""Bounded private diagnostics; reads kernel state without changing the stack.

Output may contain public peer addresses. Keep it private; never package it.
WireGuard private keys and full configurations are deliberately not requested.
"""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import time

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if os.geteuid()!=0:p.error('root required for complete kernel diagnostics')
    parent=a.output.parent
    if parent.is_symlink() or parent.stat().st_uid!=0 or parent.stat().st_mode&0o022:p.error('protected root-owned output directory required')
    def read(args):
        r=subprocess.run(args,capture_output=True,text=True,timeout=5)
        return dict(returncode=r.returncode,stdout=r.stdout[:32768],stderr=r.stderr[:1024])
    report=dict(timestamp=time.time(),boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
    report['wg']={field:read(['ip','netns','exec','ngt-site-main','wg','show','wg0',field]) for field in ('endpoints','latest-handshakes','transfer')}
    report['carrier_tcp']=read(['ss','-tinH','( sport = :443 or dport = :443 )'])
    fd=os.open(a.output,os.O_APPEND|os.O_CREAT|os.O_WRONLY|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'a') as handle:
        info=os.fstat(handle.fileno())
        if info.st_uid!=0 or info.st_mode&0o777!=0o600 or not stat.S_ISREG(info.st_mode):raise ValueError('unsafe diagnostics file')
        if info.st_size<4*1024*1024:handle.write(json.dumps(report)+'\n')

if __name__=='__main__':main()
