#!/usr/bin/env python3
"""Interrupt only the explicitly named disposable reverse field carrier."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();d=a.directory.resolve()
    if os.geteuid()!=0 or str(d)!='/opt/nextgen-field-a':p.error('root and exact owned field directory required')
    report=dict(started=time.time(),checks=[]);peer='10.77.240.1';ns='ngt-site-field';child=None
    def run(label,args,check=True):
        r=subprocess.run([str(v) for v in args],capture_output=True,text=True,timeout=90);report['checks'].append(dict(name=label,returncode=r.returncode,stdout=r.stdout,stderr=r.stderr))
        if check and r.returncode:raise RuntimeError(label+': '+r.stderr)
        return r
    def probe(label):return run(label,['ip','netns','exec',ns,'python3',d/'site_probe.py','probe','--peer',peer,'--peer','fd77:240::1'])
    try:
        probe('before_outage')
        code='''import socket,sys
s=socket.create_connection(("10.77.240.1",21901),timeout=8);s.settimeout(45)
for line in sys.stdin:
 b=line.encode();s.sendall(b);r=b""
 while len(r)<len(b):
  chunk=s.recv(len(b)-len(r))
  if not chunk:raise RuntimeError("EOF")
  r+=chunk
 assert r==b
 print("echo-ok",flush=True)
s.close()
'''
        child=subprocess.Popen(['ip','netns','exec',ns,'python3','-u','-c',code],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        def exchange(value):
            child.stdin.write(value+'\n');child.stdin.flush()
            if child.stdout.readline().strip()!='echo-ok':raise RuntimeError('existing TCP session did not echo')
        exchange('before-restart')
        run('stop_owned_carrier',['systemctl','stop','nextgen-field-reverse-carrier.service'])
        for address in (peer,'fd77:240::1'):
            r=run('outage_ping',['ip','netns','exec',ns,'ping','-c','1','-W','2',address],False)
            if r.returncode==0:raise RuntimeError('traffic escaped stopped carrier')
        r=run('no_underlay_default',['ip','-n',ns,'route','get','203.0.113.1'],False)
        if r.returncode==0:raise RuntimeError('unexpected site underlay route')
        start=time.monotonic()
        run('start_replacement_carrier',['systemd-run','--unit=nextgen-field-recovered-carrier','--property=RuntimeMaxSec=1800',d/'nextgen-tunnel','engine-run','-binary',d/'sing-box','-sha256','606f883d1aa3c624f38aa3f99bf0df02e3999f9aa0ff5826e0dd9c1b9f964baf','-config',d/'carrier.json'])
        for _ in range(20):
            if run('recovery_ping',['ip','netns','exec',ns,'ping','-c','1','-W','2',peer],False).returncode==0:break
        else:raise RuntimeError('recovery deadline')
        report['recovery_ping_seconds']=time.monotonic()-start
        exchange('after-restart');report['existing_tcp_survived']=True
        probe('after_outage');report['success']=True
    except Exception as exc:report.update(success=False,error=str(exc))
    finally:
        if child:
            child.stdin.close()
            try:child.wait(timeout=5)
            except subprocess.TimeoutExpired:child.terminate();child.wait(timeout=5)
        report['finished']=time.time();a.output.write_text(json.dumps(report,indent=2));print(json.dumps(dict(success=report.get('success',False),output=str(a.output))))
    raise SystemExit(0 if report.get('success') else 1)

if __name__=='__main__':main()
