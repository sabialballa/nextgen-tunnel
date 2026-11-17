#!/usr/bin/env python3
"""Prove a real ancillary-command timeout cannot terminate traffic workers."""
import argparse
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import path_compare


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if os.geteuid()!=0 or not Path('/etc/nextgen-lab-owned').exists():p.error('marked disposable root lab required')
    children=[];prior_path=os.environ.get('PATH','');result=dict(success=False,started=time.time())
    try:
        with tempfile.TemporaryDirectory(dir='/var/lib/nextgen-stack-lab',prefix='sampler-') as directory:
            d=Path(directory);secret=d/'secret';secret.write_bytes(secrets.token_bytes(32));secret.chmod(0o600)
            for ns,port in ((None,29401),('ngt-site-main',21901)):
                command=(['ip','netns','exec',ns] if ns else [])+[sys.executable,str(Path(path_compare.__file__)),'server','--secret',str(secret),'--allow','127.0.0.1','--bind','127.0.0.1','--port',str(port)]
                children.append(subprocess.Popen(command,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,start_new_session=True))
            ready=time.monotonic()+15
            while True:
                try:
                    with socket.create_connection(('127.0.0.1',29401),timeout=.3):pass
                    check=subprocess.run(['ip','netns','exec','ngt-site-main',sys.executable,'-c','import socket;socket.create_connection(("127.0.0.1",21901),timeout=.3).close()'],capture_output=True,timeout=3)
                    if check.returncode==0:break
                except OSError:pass
                if time.monotonic()>ready:raise RuntimeError('fixture server readiness timeout')
                time.sleep(.2)
            (d/'bin').mkdir();fake=d/'bin/ss';fake.write_text('#!/usr/bin/python3\nimport time\ntime.sleep(6)\n');fake.chmod(0o755)
            os.environ['PATH']=str(d/'bin')+':'+prior_path
            config=argparse.Namespace(secret=secret,seconds=12,output=d/'result.json',direct_peer='127.0.0.1',peer=['127.0.0.1'],namespace='ngt-site-main',engine_unit='nextgen-engine.service',carrier_tcp_port=443,no_watchdog=True)
            path_compare.run(config);r=json.loads(config.output.read_text())
            failures=[v for v in r['sampling_errors'] if v['component']=='tcp' and v['error']=='TimeoutExpired']
            assert failures and r['complete'] and all(p['complete'] and all(f['received']>0 for f in p['flows'].values()) for p in r['paths'].values())
            result.update(success=True,real_5s_sampling_timeouts=len(failures),traffic_workers_completed=True,measurement_revision=r['measurement_revision'],duration_seconds=r['elapsed_seconds'],main_stack_modified=False)
    except Exception as exc:result['error']=str(exc)
    finally:
        os.environ['PATH']=prior_path
        for child in children:
            if child.poll() is None:
                try:os.killpg(child.pid,signal.SIGTERM)
                except ProcessLookupError:pass
                child.wait(timeout=10)
        result['finished']=time.time();a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
    raise SystemExit(0 if result['success'] else 1)


if __name__=='__main__':main()
