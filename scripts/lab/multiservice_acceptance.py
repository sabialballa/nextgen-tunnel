#!/usr/bin/env python3
"""Exercise real content generation and engine validation in the owned Linux VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import stack_install

def main():
    p=argparse.ArgumentParser();p.add_argument('--engine',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if os.geteuid()!=0 or not Path('/etc/nextgen-lab-owned').exists():p.error('marked disposable root VM required')
    work=Path('/var/lib/nextgen-stack-lab');site=json.loads((work/'site.json').read_text());site['endpoint']='127.0.0.1:51811'
    core=ROOT/'bin/nextgen-tunnel';core_sha=hashlib.sha256(core.read_bytes()).hexdigest();engine_sha=hashlib.sha256(a.engine.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(dir=work,prefix='multiservice-') as directory:
        d=Path(directory);site_path=d/'site.json';site_path.write_text(json.dumps(site))
        config=dict(inbounds=[dict(type='direct',tag='site',listen='127.0.0.1',listen_port=51811,network='udp'),dict(type='direct',tag='other',listen='127.0.0.1',listen_port=51822,network='udp')],outbounds=[dict(type='direct',tag='egress')],route=dict(final='egress'))
        cfg=d/'engine.json';cfg.write_text(json.dumps(config));args=argparse.Namespace(binary=core,sha256=core_sha,engine=a.engine,engine_sha256=engine_sha,engine_config=cfg,site_config=site_path)
        files=stack_install.content(args);assert json.loads(files['/etc/nextgen-stack/redundancy.json'])==dict(enabled=False),'ordinary multiple UDP services changed into fanout'
        config['inbounds'][0]['listen_port']=51812;config['inbounds'][1]['listen_port']=51813;config['outbounds']=[dict(type='direct',tag='a'),dict(type='direct',tag='b')];config['route']=dict(rules=[dict(inbound=['site'],action='route',outbound='a'),dict(inbound=['other'],action='route',outbound='b')],final='a');cfg.write_text(json.dumps(config))
        files=stack_install.content(args);relay=d/'redundancy.json';relay.write_bytes(files['/etc/nextgen-stack/redundancy.json']);assert json.loads(relay.read_text())['enabled']
        subprocess.run([str(core),'engine-check','-binary',str(a.engine),'-sha256',engine_sha,'-config',str(cfg),'-redundancy-config',str(relay)],check=True)
        site.pop('endpoint');site['redundant_listener_port']=51852;site_path.write_text(json.dumps(site))
        config['route']=dict(rules=[dict(ip_cidr=['127.0.0.1/32'],port=[51852],action='route',outbound='a'),dict(action='reject')]);cfg.write_text(json.dumps(config))
        files=stack_install.content(args);relay.write_bytes(files['/etc/nextgen-stack/redundancy.json']);assert json.loads(relay.read_text())==dict(enabled=True,mode='listener',listen='127.0.0.1:51852',target=f"127.0.0.1:{site['listen_port']}")
        subprocess.run([str(core),'engine-check','-binary',str(a.engine),'-sha256',engine_sha,'-config',str(cfg),'-redundancy-config',str(relay)],check=True)
    result=dict(success=True,ordinary_multiple_udp_services_preserved=True,explicit_independent_carriers_enable_redundancy=True,passive_reverse_fanout_generated=True,generated_config_validated_by_real_core_and_engine=True,core_sha256=core_sha)
    a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))

if __name__=='__main__':main()
