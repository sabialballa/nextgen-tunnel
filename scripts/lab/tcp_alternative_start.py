#!/usr/bin/env python3
"""Start only the owned, temporary alternative after the main hour completes."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from tcp_alternative import UNIT

CORE=Path('/usr/local/lib/nextgen-stack/nextgen-tunnel')
ENGINE=Path('/usr/local/lib/nextgen-stack/sing-box')
CORE_SHA='96cec972279a1d7a02f13aed4dd6fd3029b581576edd8f48bc598abb9726433f'
ENGINE_SHA='606f883d1aa3c624f38aa3f99bf0df02e3999f9aa0ff5826e0dd9c1b9f964baf'


def main():
    p=argparse.ArgumentParser();p.add_argument('--role',choices=('listener','initiator'),required=True);a=p.parse_args()
    d=Path('/opt/nextgen-stack-stage/tcp-alt');marker=d/'owner.json'
    if os.geteuid()!=0 or d.is_symlink() or d.stat().st_uid!=0 or d.stat().st_mode&0o077:p.error('owned protected root test directory required')
    owner=json.loads(marker.read_text());assert owner['kind']=='nextgen-tcp-alternative' and owner['role']==a.role
    baseline=json.loads(Path('/opt/nextgen-stack-stage/two-hour-rc3/soak.json').read_text())
    assert baseline['complete'] and baseline['elapsed_seconds']>=3600,'main hour must finish before adding alternative traffic'
    assert any(v['timeouts'] for k,v in baseline['paths']['site']['flows'].items() if k.endswith('udp')),'conditional alternative requires observed UDP deadline misses'
    assert hashlib.sha256(CORE.read_bytes()).hexdigest()==CORE_SHA and hashlib.sha256(ENGINE.read_bytes()).hexdigest()==ENGINE_SHA
    def run(args):return subprocess.run([str(v) for v in args],capture_output=True,text=True,check=True,timeout=60)
    unit='nextgen-alt-engine.service'
    assert run(['systemctl','show',unit,'-p','LoadState','--value']).stdout.strip()=='not-found','refusing an existing unit'
    credentials=dict(config=d/'engine.json',relay=d/'relay.json',ca=d/'ca.crt',cert=d/('server.crt' if a.role=='listener' else 'client.crt'),key=d/('server.key' if a.role=='listener' else 'client.key'))
    for path in credentials.values():assert not path.is_symlink() and path.stat().st_uid==0 and path.stat().st_mode&0o077==0
    content=(d/'engine.json').read_text()
    for name,path in credentials.items():content=content.replace(UNIT+name,str(path))
    with tempfile.NamedTemporaryFile(mode='w',dir=d,prefix='check-',suffix='.json') as check:
        check.write(content);check.flush()
        result=subprocess.run([str(CORE),'engine-check','-binary',str(ENGINE),'-sha256',ENGINE_SHA,'-config',check.name,'-redundancy-config',str(d/'relay.json')],capture_output=True,text=True,timeout=60)
        log=d/'validation.log';log.write_text(result.stdout+result.stderr);log.chmod(0o600)
        if result.returncode:raise RuntimeError('alternative engine-check failed; protected log retained')
    run(['python3','/usr/local/lib/nextgen-stack/site.py','create','--config',d/'site.json','--apply'])
    owner['namespace_created']=True;marker.write_text(json.dumps(owner));marker.chmod(0o600)
    command=['systemd-run','--collect','--unit=nextgen-alt-engine','--property=DynamicUser=yes','--property=NoNewPrivileges=yes','--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=MemoryMax=128M','--property=TasksMax=64','--property=RuntimeMaxSec=1200','--property=UMask=0077']
    for name,path in credentials.items():command+=['--property=LoadCredential='+name+':'+str(path)]
    command+=['--',str(CORE),'engine-run','-binary',str(ENGINE),'-sha256',ENGINE_SHA,'-config',UNIT+'config','-redundancy-config',UNIT+'relay']
    run(command);owner['engine_started']=True;owner['invocation_id']=run(['systemctl','show',unit,'-p','InvocationID','--value']).stdout.strip();marker.write_text(json.dumps(owner));marker.chmod(0o600)
    print(json.dumps(dict(alternative_started=True,main_stack_modified=False,namespace='ngt-site-alt',tls_minimum='1.3',smux=False)))


if __name__=='__main__':main()
