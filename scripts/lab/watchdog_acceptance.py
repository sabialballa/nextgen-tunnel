#!/usr/bin/env python3
"""Real watchdog-triggered recovery after an owned local WG carrier outage."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
def main():
    p=argparse.ArgumentParser();p.add_argument('--engine',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if os.geteuid()!=0 or not Path('/etc/nextgen-lab-owned').exists():p.error('marked disposable root VM required')
    work=Path('/var/lib/nextgen-stack-lab');report=dict(started=time.time(),checks=[]);relay=None;peer_created=False
    def run(label,args,check=True):
        r=subprocess.run([str(v) for v in args],capture_output=True,text=True,timeout=120);report['checks'].append(dict(name=label,returncode=r.returncode,stdout=r.stdout,stderr=r.stderr));print(label,r.returncode,flush=True)
        if check and r.returncode:raise RuntimeError(label+': '+r.stderr[-1000:])
        return r
    def update(site):
        run('update_site',[sys.executable,ROOT/'scripts/stack_install.py','update','--binary',ROOT/'bin/nextgen-tunnel','--sha256',hashlib.sha256((ROOT/'bin/nextgen-tunnel').read_bytes()).hexdigest(),'--engine',a.engine,'--engine-sha256',hashlib.sha256(a.engine.read_bytes()).hexdigest(),'--engine-config',work/'configs/server.json','--site-config',site,'--apply'])
    before=run('routes_before',['ip','-j','route','show']).stdout
    try:
        peer=dict(name='ngt-site-watchpeer',private_key_file=str(work/'peer-keys/private.key'),peer_public_key=(work/'keys/public.key').read_text().strip(),addresses=['10.79.0.2/30','fd79::2/126'],remote_routes=['10.79.0.1/32','fd79::1/128'],listen_port=51892,mtu=1280)
        peer_path=work/'watchpeer.json';peer_path.write_text(json.dumps(peer));run('create_peer',[sys.executable,ROOT/'scripts/site.py','create','--config',peer_path,'--apply']);peer_created=True
        def launch():return subprocess.Popen([sys.executable,str(ROOT/'scripts/lab/udp_carrier.py'),'--peer','127.0.0.1','--peer-port','51892','--listen-port','51893'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        relay=launch();site=json.loads((work/'site.json').read_text());site['endpoint']='127.0.0.1:51893';site_path=work/'initiator.json';site_path.write_text(json.dumps(site));update(site_path)
        for _ in range(15):
            if run('warmup',['ip','netns','exec','ngt-site-main','ping','-c','1','-W','1','10.79.0.2'],False).returncode==0:break
        else:raise RuntimeError('initial WG handshake failed')
        state_path=Path('/var/lib/nextgen-stack-watchdog/state.json')
        run('initial_watchdog',['systemctl','start','nextgen-site-watchdog.service']);before_state=json.loads(state_path.read_text())
        relay.terminate();relay.wait(timeout=5);relay=None;start=time.monotonic()
        while time.monotonic()-start<70:
            time.sleep(2);state=json.loads(state_path.read_text())
            if state.get('engine_restarts',0)>before_state.get('engine_restarts',0) and state.get('rekeys',0)>before_state.get('rekeys',0):break
        else:raise RuntimeError('watchdog did not rekey and restart the unavailable initiating carrier')
        report['watchdog_actions']=state;relay=launch();recovery=time.monotonic()
        for _ in range(20):
            if run('recover_ping',['ip','netns','exec','ngt-site-main','ping','-c','1','-W','2','10.79.0.2'],False).returncode==0:break
            time.sleep(1)
        else:raise RuntimeError('site did not recover after restoring carrier')
        report['carrier_restore_to_ping_seconds']=time.monotonic()-recovery
        run('ipv6_recovered',['ip','netns','exec','ngt-site-main','ping','-6','-c','2','-W','2','fd79::2']);report['success']=True
    except Exception as exc:report.update(success=False,error=str(exc))
    finally:
        if relay:relay.terminate();relay.wait(timeout=5)
        if peer_created:run('remove_peer',[sys.executable,ROOT/'scripts/site.py','remove','--name','ngt-site-watchpeer','--apply'],False)
        try:update(work/'site.json')
        except Exception as exc:report.update(success=False,restore_error=str(exc))
        report['host_routes_unchanged']=before==run('routes_after',['ip','-j','route','show']).stdout;report['success']=report.get('success',False) and report['host_routes_unchanged'];report['finished']=time.time();a.output.write_text(json.dumps(report,indent=2));print(json.dumps(dict(success=report['success'],output=str(a.output))))
    raise SystemExit(0 if report['success'] else 1)
if __name__=='__main__':main()
