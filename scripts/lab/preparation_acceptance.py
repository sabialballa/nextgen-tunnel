#!/usr/bin/env python3
"""Validate generated four-carrier profiles in the disposable Linux lab."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]


def main():
    p=argparse.ArgumentParser();p.add_argument('--engine',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if os.geteuid()!=0 or not Path('/etc/nextgen-lab-owned').exists():p.error('marked root lab required')
    work=Path('/var/lib/nextgen-stack-lab');core=ROOT/'bin/nextgen-tunnel'
    with tempfile.TemporaryDirectory(dir=work,prefix='prepare-rc3-') as directory:
        d=Path(directory);generated={}
        for role,name in (('listener','server'),('initiator','client')):
            cfg=json.loads((work/'configs'/(name+'.json')).read_text())
            if role=='listener':
                inbound=next(v for v in cfg['inbounds'] if v['type']=='vless');inbound['tls']['reality']['handshake']['server']='203.0.113.1'
            src=d/(name+'.json');src.write_text(json.dumps(cfg));out=d/(role+'.json')
            subprocess.run([sys.executable,str(ROOT/'scripts/stack_prepare.py'),'--role',role,'--redundant','--carriers','4','--source',str(src),'--output',str(out),'--remote-wg-port','51891'],check=True,capture_output=True)
            subprocess.run([str(core),'engine-check','-binary',str(a.engine),'-sha256',hashlib.sha256(a.engine.read_bytes()).hexdigest(),'-config',str(out)],check=True,capture_output=True)
            generated[role]=json.loads(out.read_text())
        c=generated['initiator'];assert len(c['inbounds'])==len(c['outbounds'])==len(c['route']['rules'])==4
        assert {v['listen_port'] for v in c['inbounds']}=={51812,51813,51814,51815}
        assert all(v['override_port']==51892 for v in c['inbounds'])
        assert len({r['outbound'] for r in c['route']['rules']})==4
        assert all(v['multiplex']['max_connections']==1 for v in c['outbounds'])
        assert generated['listener']['route']['rules'][0]['port']==[51892]
        default=d/'default-initiator.json'
        subprocess.run([sys.executable,str(ROOT/'scripts/stack_prepare.py'),'--role','initiator','--redundant','--source',str(src),'--output',str(default),'--remote-wg-port','51891'],check=True,capture_output=True)
        assert len(json.loads(default.read_text())['outbounds'])==2
        subprocess.run([str(core),'engine-check','-binary',str(a.engine),'-sha256',hashlib.sha256(a.engine.read_bytes()).hexdigest(),'-config',str(default)],check=True,capture_output=True)
    r=dict(success=True,default_two_carriers=True,explicit_four_independent_carriers=True,listener_and_initiator_destination_match=True,real_core_engine_check_passed=True,core_sha256=hashlib.sha256(core.read_bytes()).hexdigest())
    a.output.write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r))


if __name__=='__main__':main()
