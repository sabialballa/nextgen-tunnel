#!/usr/bin/env python3
"""Owned, fail-closed TUN application namespace without host routing changes.

Only loopback is created; a separate engine puts its TUN into this namespace.
There is no physical/veth underlay inside it, so removing TUN leaves no egress.
"""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess

STATE=Path('/var/lib/nextgen-namespaces')
def run(args):return subprocess.run(args,check=True,capture_output=True,text=True).stdout
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('create','remove','status'));p.add_argument('--name',default='ngt-apps');p.add_argument('--apply',action='store_true');a=p.parse_args()
    if not re.fullmatch(r'ngt-[a-z0-9_-]{1,24}',a.name):p.error('dedicated ngt- namespace name required')
    marker=STATE/(a.name+'.json');resolver=Path('/etc/netns')/a.name/'resolv.conf'
    if a.action=='status':print(run(['ip','-n',a.name,'-j','link','show']));return
    if not a.apply:print(json.dumps({'action':a.action,'namespace':a.name,'host_routes_changed':False,'host_firewall_changed':False}));return
    if os.geteuid()!=0:p.error('--apply requires root')
    if STATE.is_symlink() or marker.is_symlink() or resolver.is_symlink():p.error('symlink in owned paths')
    STATE.mkdir(mode=0o700,exist_ok=True)
    if STATE.stat().st_uid!=0 or STATE.stat().st_mode&0o022:p.error('unsafe ownership state')
    existing={line.split()[0] for line in run(['ip','netns','list']).splitlines() if line.strip()}
    if a.action=='create':
        if a.name in existing:
            if not marker.exists():p.error('unmanaged namespace exists')
            if json.loads(marker.read_text()).get('inode')!=Path('/run/netns',a.name).stat().st_ino:p.error('namespace ownership mismatch')
            print('unchanged');return
        if resolver.parent.exists() and not marker.exists():p.error('unmanaged namespace configuration exists')
        marker.write_text(json.dumps({'name':a.name,'resolver':str(resolver)}));marker.chmod(0o600)
        try:
            run(['ip','netns','add',a.name]);marker.write_text(json.dumps({'name':a.name,'resolver':str(resolver),'inode':Path('/run/netns',a.name).stat().st_ino}));run(['ip','-n',a.name,'link','set','lo','up'])
            resolver.parent.mkdir(parents=True,exist_ok=True);resolver.write_text('nameserver 172.29.250.2\noptions timeout:2 attempts:1\n')
        except BaseException:
            if a.name in {line.split()[0] for line in run(['ip','netns','list']).splitlines()}:run(['ip','netns','del',a.name])
            marker.unlink(missing_ok=True);raise
        print('created; no egress until the TUN engine starts')
    else:
        if not marker.exists():
            if a.name in existing:p.error('unmanaged namespace; refusing deletion')
            print('absent');return
        if a.name in existing:
            if json.loads(marker.read_text()).get('inode')!=Path('/run/netns',a.name).stat().st_ino:p.error('namespace ownership mismatch')
            links=json.loads(run(['ip','-n',a.name,'-j','link','show']))
            if run(['ip','netns','pids',a.name]).strip() or any(v['ifname']!='lo' for v in links):p.error('stop engine and namespace applications before removal')
            run(['ip','netns','del',a.name])
        resolver.unlink(missing_ok=True)
        try:resolver.parent.rmdir()
        except OSError:pass
        marker.unlink();print('removed owned namespace')
if __name__=='__main__':main()
