#!/usr/bin/env python3
"""Remove only this owned experiment; preserve its reports and the main stack."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    d=Path('/opt/nextgen-stack-stage/tcp-alt');code=Path('/usr/local/lib/nextgen-tcp-alt-test');main_code=Path('/usr/local/lib/nextgen-two-hour-test')
    if os.geteuid()!=0 or d.is_symlink() or d.stat().st_uid!=0:raise RuntimeError('protected owned root workspace required')
    owner=json.loads((d/'owner.json').read_text());assert owner['kind']=='nextgen-tcp-alternative'
    for filename in ('paired-main','alternative'):
        r=json.loads((d/(filename+'.json')).read_text());assert r['complete'] and r['elapsed_seconds']>=300
    baseline=Path('/opt/nextgen-stack-stage/two-hour-rc3');r=json.loads((baseline/'soak.json').read_text());assert r['complete'] and r['elapsed_seconds']>=3600
    def call(args):return subprocess.run(args,capture_output=True,text=True,check=True,timeout=60)
    load=call(['systemctl','show','nextgen-alt-engine.service','-p','LoadState','--value']).stdout.strip()
    if load!='not-found':assert call(['systemctl','show','nextgen-alt-engine.service','-p','InvocationID','--value']).stdout.strip()==owner['invocation_id'],'unexpected alternative unit owner'
    for unit in ('nextgen-alt-probe.service','nextgen-two-paired.service','nextgen-alt-echo.service','nextgen-alt-engine.service','nextgen-two-hour-final.service','nextgen-two-hour.service','nextgen-two-site.service','nextgen-two-direct.service'):
        if call(['systemctl','show',unit,'-p','LoadState','--value']).stdout.strip()!='not-found':call(['systemctl','stop',unit])
    call(['python3','/usr/local/lib/nextgen-stack/site.py','remove','--name','ngt-site-alt','--apply'])
    assert not Path('/run/netns/ngt-site-alt').exists()
    files=['engine.json','client-export.json','relay.json','site.json','server.key','server.crt','client.key','client.crt','ca.crt','peer.key','validation.log','wg/private.key','wg/public.key']
    for name in files:
        p=d/name
        if p.exists():assert not p.is_symlink() and p.is_file() and p.stat().st_uid==0;p.unlink()
    (d/'wg').rmdir()
    expected={'path_compare.py','tcp_alternative.py','tcp_alternative_start.py','tcp_alternative_cleanup.py'}
    assert not code.is_symlink() and {p.name for p in code.iterdir()}==expected
    for name in expected:
        p=code/name;assert not p.is_symlink() and p.stat().st_uid==0;p.unlink()
    code.rmdir()
    assert not main_code.is_symlink() and {p.name for p in main_code.iterdir()}=={'path_compare.py'}
    p=main_code/'path_compare.py';assert hashlib.sha256(p.read_bytes()).hexdigest()=='545feab6c0c88ee2cd61220a00701bf6795515a777947a13ab7e6bf1b3dd696f';p.unlink();main_code.rmdir()
    secret=baseline/'secret';assert not secret.is_symlink() and secret.stat().st_uid==0 and secret.stat().st_size==32;secret.unlink()
    marker=Path('/var/lib/nextgen-stack-installer/ownership.json');assert marker.read_bytes()==(d/'main-ownership-before.json').read_bytes()
    owned=json.loads(marker.read_text());assert all(hashlib.sha256(Path(p).read_bytes()).hexdigest()==v for p,v in owned['hashes'].items())
    ports='( sport = :24443 or sport = :52811 or sport = :52812 or sport = :52813 or sport = :52850 or sport = :52851 or sport = :52860 or sport = :29401 )'
    assert not call(['ss','-lntupH',ports]).stdout.strip(),'temporary listener still present'
    result=dict(success=True,wall_time=time.time(),temporary_namespace_removed=True,temporary_credentials_removed=True,test_helpers_removed=True,test_listeners_closed=True,main_owned_files_unchanged=True,main_ownership_marker_unchanged=True)
    q=d/'cleanup.json';q.write_text(json.dumps(result,indent=2)+'\n');q.chmod(0o600);print(json.dumps(result))


if __name__=='__main__':main()
