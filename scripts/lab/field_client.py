#!/usr/bin/env python3
"""Create bounded loopback-only field carriers from an existing private profile."""
import argparse
import json
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--directory',type=Path,required=True)
    p.add_argument('--path',choices=('auto','hy2','reality'),default='auto')
    p.add_argument('--site-target-port',type=int,default=51820)
    a=p.parse_args();d=a.directory.resolve()
    if not 1024<=a.site_target_port<=65535:p.error('invalid site target port')
    cfg=json.loads((d/'engine-client.json').read_text())
    cfg['inbounds']=[dict(type='direct',tag=tag,listen='127.0.0.1',listen_port=port,network=network,override_address='127.0.0.1',override_port=target) for tag,port,network,target in [('tcp-echo',19821,'tcp',19801),('udp-echo',19822,'udp',19802),('site',51811,'udp',a.site_target_port)]]
    cfg['route']={'final':a.path}
    cfg.pop('dns',None)
    target=d/'carrier.json';target.write_text(json.dumps(cfg,indent=2));target.chmod(0o600)
    print(json.dumps(dict(path=a.path,loopback_only=True)))

if __name__=='__main__':main()
