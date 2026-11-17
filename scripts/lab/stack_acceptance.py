#!/usr/bin/env python3
"""Exercise real stack transactions only in the owned disposable Linux VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
def main():
    p=argparse.ArgumentParser();p.add_argument('--engine',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if os.geteuid()!=0 or not Path('/etc/nextgen-lab-owned').exists():p.error('marked disposable root VM required')
    report=dict(started=time.time(),checks=[]);work=Path('/var/lib/nextgen-stack-lab');work.mkdir(mode=0o700,exist_ok=True);binary=ROOT/'bin/nextgen-tunnel';installer=ROOT/'scripts/stack_install.py'
    def run(label,args,expected=0):
        r=subprocess.run([str(v) for v in args],capture_output=True,text=True,timeout=120);report['checks'].append(dict(name=label,returncode=r.returncode,expected=expected,stdout=r.stdout,stderr=r.stderr));print(label,r.returncode,flush=True)
        if r.returncode!=expected:raise RuntimeError(label+': '+r.stderr[-1500:])
        return r
    core_sha=hashlib.sha256(binary.read_bytes()).hexdigest();engine_sha=hashlib.sha256(a.engine.read_bytes()).hexdigest()
    def install(action,config=None,expected=0):return run(action,[sys.executable,installer,action,'--binary',binary,'--sha256',core_sha,'--engine',a.engine,'--engine-sha256',engine_sha,'--engine-config',config or work/'configs/server.json','--site-config',work/'site.json','--apply'],expected)
    before=subprocess.check_output(['ip','-j','route','show'],text=True);firewall=subprocess.check_output(['nft','list','ruleset'],text=True)
    try:
        if not (work/'profile/profile.json').exists():run('init',[binary,'engine-init','-dir',work/'profile','-server-ip','127.0.0.1'])
        cfg=json.loads((work/'profile/profile.json').read_text());cfg.update(quic_port=28444,tcp_port=28445);(work/'profile/profile.json').write_text(json.dumps(cfg))
        if not (work/'configs').exists():run('plan',[binary,'engine-plan','-profile',work/'profile/profile.json','-output',work/'configs'])
        for name in ('keys','peer-keys'):
            if not (work/name).exists():run('keygen',[sys.executable,ROOT/'scripts/site.py','keygen','--directory',work/name])
        site=dict(name='ngt-site-main',private_key_file=str(work/'keys/private.key'),peer_public_key=(work/'peer-keys/public.key').read_text().strip(),addresses=['10.79.0.1/30','fd79::1/126'],remote_routes=['10.79.0.2/32','fd79::2/128'],listen_port=51891,mtu=1280)
        (work/'site.json').write_text(json.dumps(site))
        install('install');pid=run('engine_pid',['systemctl','show','nextgen-engine','-p','MainPID','--value']).stdout.strip();install('install')
        if pid!=run('same_pid',['systemctl','show','nextgen-engine','-p','MainPID','--value']).stdout.strip():raise RuntimeError('idempotent install restarted engine')
        run('unit_verify',['systemd-analyze','verify','/etc/systemd/system/nextgen-site.service','/etc/systemd/system/nextgen-engine.service'])
        bad=json.loads((work/'configs/server.json').read_text());bad['invalid_stack_test_option']=True;(work/'invalid.json').write_text(json.dumps(bad));failure=install('update',work/'invalid.json',1)
        if 'engine-check' not in failure.stderr:raise RuntimeError('invalid configuration did not reach engine validation')
        run('rollback_active',[sys.executable,installer,'status'])
        occupied=socket.socket();occupied.bind(('127.0.0.1',28999));occupied.listen()
        try:
            bad=json.loads((work/'configs/server.json').read_text());bad['inbounds'][1]['listen_port']=28999;(work/'conflict.json').write_text(json.dumps(bad));failure=install('update',work/'conflict.json',1)
            if not any(v in failure.stderr for v in ('engine-owned listener','readiness deadline','is-active')):raise RuntimeError('bind conflict failed before service readiness test')
        finally:occupied.close()
        run('rollback_after_bind_conflict',[sys.executable,installer,'status'])
        code='''import sys,os,json
sys.path.insert(0,"%s")
import stack_install as s
s.snapshot();s.atomic(s.ETC/"engine.json",b"partial crash write");os._exit(73)
''' % str(ROOT/'scripts')
        run('crash_after_journal',[sys.executable,'-c',code],73);run('recover',[sys.executable,installer,'recover','--apply']);run('recover_idempotent',[sys.executable,installer,'recover','--apply']);run('recovered_status',[sys.executable,installer,'status'])
        original=Path('/etc/nextgen-stack/engine.json').read_bytes();Path('/etc/nextgen-stack/engine.json').write_bytes(original+b' ')
        run('refuse_modified_uninstall',[sys.executable,installer,'uninstall','--apply'],1);Path('/etc/nextgen-stack/engine.json').write_bytes(original)
        run('uninstall',[sys.executable,installer,'uninstall','--apply']);run('uninstall_again',[sys.executable,installer,'uninstall','--apply']);install('install')
        report['success']=True
    except Exception as exc:report.update(success=False,error=str(exc))
    finally:
        report['host_routes_unchanged']=before==subprocess.check_output(['ip','-j','route','show'],text=True);report['host_firewall_unchanged']=firewall==subprocess.check_output(['nft','list','ruleset'],text=True);report['success']=report.get('success',False) and report['host_routes_unchanged'] and report['host_firewall_unchanged'];report['finished']=time.time();a.output.write_text(json.dumps(report,indent=2));print(json.dumps(dict(success=report['success'],output=str(a.output))))
    raise SystemExit(0 if report['success'] else 1)
if __name__=='__main__':main()
