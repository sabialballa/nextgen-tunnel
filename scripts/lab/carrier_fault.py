#!/usr/bin/env python3
"""Briefly drop exactly one owned engine TCP flow; always restore the test table."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

def main():
    p=argparse.ArgumentParser();p.add_argument('--peer',required=True);p.add_argument('--seconds',type=int,default=20);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    ipaddress.IPv4Address(a.peer)
    if os.geteuid()!=0 or not 1<=a.seconds<=25:p.error('root and bounded fault interval required')
    if not Path('/var/lib/nextgen-stack-installer/ownership.json').exists():p.error('owned installed stack required')
    def run(args,check=True,**kw):return subprocess.run(args,capture_output=True,text=True,timeout=5,check=check,**kw)
    cfg=json.loads(Path('/etc/nextgen-stack/engine.json').read_text())
    if sum(v.get('server')==a.peer and v.get('server_port')==443 for v in cfg['outbounds'])<2:p.error('two independent configured peer carriers required')
    group=run(['systemctl','show','nextgen-engine.service','-p','ControlGroup','--value']).stdout.strip()
    if group!='/system.slice/nextgen-engine.service':p.error('unexpected engine cgroup')
    pids=set((Path('/sys/fs/cgroup')/group.lstrip('/')/'cgroup.procs').read_text().split());ports=set()
    for line in run(['ss','-Htnp','state','established']).stdout.splitlines():
        addresses=re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}:\d+',line)
        if len(addresses)>=2 and addresses[1]==a.peer+':443' and pids.intersection(re.findall(r'pid=(\d+)',line)):ports.add(int(addresses[0].rsplit(':',1)[1]))
    if len(ports)<2:p.error('two live engine TCP connections required before fault injection')
    table='ngt_compare_fault'
    if run(['nft','list','table','inet',table],False).returncode==0:p.error('refusing an existing table')
    port=min(ports);before=run(['nft','list','ruleset']).stdout;created=False;report=dict(seconds_requested=a.seconds,local_carrier_port=port,other_live_carriers=len(ports)-1,completed=False)
    def stop(signum,frame):raise SystemExit('test interrupted')
    signal.signal(signal.SIGTERM,stop)
    try:
        run(['nft','add','table','inet',table]);created=True
        rules=f'add chain inet {table} output {{ type filter hook output priority -190; policy accept; }}\nadd chain inet {table} input {{ type filter hook input priority -190; policy accept; }}\nadd rule inet {table} output ip daddr {a.peer} tcp sport {port} tcp dport 443 drop\nadd rule inet {table} input ip saddr {a.peer} tcp sport 443 tcp dport {port} drop\n'
        run(['nft','-f','-'],input=rules);report['started_wall_time']=time.time();time.sleep(a.seconds);report['completed']=True
    finally:
        if created:run(['nft','delete','table','inet',table])
        report['finished_wall_time']=time.time();after=run(['nft','list','ruleset']).stdout;report['firewall_restored']=before==after;report['before_rules_sha256']=hashlib.sha256(before.encode()).hexdigest();a.output.write_text(json.dumps(report,indent=2));a.output.chmod(0o600)
    print(json.dumps(report));raise SystemExit(0 if report['completed'] and report['firewall_restored'] else 1)

if __name__=='__main__':main()
