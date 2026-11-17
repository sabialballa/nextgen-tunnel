#!/usr/bin/env python3
"""Exercise temporary TLS/Trojan profiles only inside the owned Linux VM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
from tcp_alternative import profiles,IDENTITY,UNIT,write_new


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if os.geteuid()!=0 or not Path('/etc/nextgen-lab-owned').exists():p.error('marked disposable root VM required')
    core=Path('/usr/local/lib/nextgen-stack/nextgen-tunnel');engine=Path('/usr/local/lib/nextgen-stack/sing-box');sha=hashlib.sha256(engine.read_bytes()).hexdigest();created=[];echo=None;result=dict(success=False,started=time.time())
    def run(args):return subprocess.run([str(x) for x in args],capture_output=True,text=True,check=True,timeout=30)
    try:
        for unit in ('nextgen-alt-engine.service','nextgen-alt-client.service'):
            if run(['systemctl','show',unit,'-p','LoadState','--value']).stdout.strip()!='not-found':raise ValueError('temporary unit already exists')
        with tempfile.TemporaryDirectory(dir='/var/lib/nextgen-stack-lab',prefix='tcp-alt-') as directory:
            d=Path(directory);run([core,'pki','-dir',d/'pki','-server-name',IDENTITY,'-client-name','site-alt'])
            server,client=profiles('127.0.0.1',secrets.token_hex(32));client=json.loads(json.dumps(client).replace(UNIT,'/run/credentials/nextgen-alt-client.service/'))
            echo=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);echo.bind(('127.0.0.1',52850))
            def echo_loop():
                while True:
                    try:data,peer=echo.recvfrom(2048);echo.sendto(data,peer)
                    except OSError:return
            threading.Thread(target=echo_loop,daemon=True).start()
            for name,cfg,relay,cert,key in (
                ('nextgen-alt-engine',server,dict(enabled=True,mode='listener',listen='127.0.0.1:52851',target='127.0.0.1:52850'),'server.crt','server.key'),
                ('nextgen-alt-client',client,dict(enabled=True,listen='127.0.0.1:52811',target='127.0.0.1:52860',backends=['127.0.0.1:52812','127.0.0.1:52813']),'client.crt','client.key')):
                config=d/(name+'.json');rel=d/(name+'-relay.json');write_new(config,cfg);write_new(rel,relay)
                credentials=dict(config=config,relay=rel,ca=d/'pki/ca.crt',cert=d/'pki'/cert,key=d/'pki'/key)
                checked=json.dumps(cfg)
                for credential,path in credentials.items():checked=checked.replace('/run/credentials/'+name+'.service/'+credential,str(path))
                check=d/(name+'-check.json');check.write_text(checked)
                run([core,'engine-check','-binary',engine,'-sha256',sha,'-config',check,'-redundancy-config',rel])
                command=['systemd-run','--collect','--unit='+name,'--property=DynamicUser=yes','--property=ProtectSystem=strict','--property=ProtectHome=yes','--property=NoNewPrivileges=yes','--property=MemoryMax=128M','--property=TasksMax=64','--property=RuntimeMaxSec=120']
                for credential,path in credentials.items():command+=['--property=LoadCredential='+credential+':'+str(path)]
                command+=['--',str(core),'engine-run','-binary',str(engine),'-sha256',sha,'-config','/run/credentials/'+name+'.service/config','-redundancy-config','/run/credentials/'+name+'.service/relay']
                run(command);created.append(name+'.service')
            deadline=time.monotonic()+25
            while True:
                try:
                    with socket.create_connection(('127.0.0.1',24443),timeout=1):break
                except OSError:
                    if time.monotonic()>deadline:raise RuntimeError('TLS listener readiness timeout')
                    time.sleep(.3)
            context=ssl.create_default_context(cafile=str(d/'pki/ca.crt'));context.minimum_version=ssl.TLSVersion.TLSv1_3
            try:
                with context.wrap_socket(socket.create_connection(('127.0.0.1',24443),timeout=2),server_hostname=IDENTITY) as conn:
                    conn.settimeout(2);conn.recv(1)
                raise RuntimeError('connection without client certificate was not rejected')
            except ssl.SSLError:result['missing_client_certificate_rejected']=True
            untrusted=ssl.create_default_context();untrusted.minimum_version=ssl.TLSVersion.TLSv1_3
            try:
                with untrusted.wrap_socket(socket.create_connection(('127.0.0.1',24443),timeout=2),server_hostname=IDENTITY):pass
                raise RuntimeError('untrusted CA was accepted')
            except ssl.SSLCertVerificationError:result['untrusted_server_ca_rejected']=True
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as probe:
                probe.bind(('127.0.0.1',52860));probe.settimeout(3)
                payload=(4).to_bytes(4,'little')+os.urandom(60);received=False
                for attempt in range(6):
                    probe.sendto(payload,('127.0.0.1',52811))
                    try:received=probe.recv(2048)==payload
                    except socket.timeout:continue
                    if received:break
                if not received:raise RuntimeError('authenticated opaque datagram did not round-trip')
            group=run(['systemctl','show','nextgen-alt-client.service','-p','ControlGroup','--value']).stdout.strip();pids=set((Path('/sys/fs/cgroup')/group.lstrip('/')/'cgroup.procs').read_text().split())
            rows=run(['ss','-tnpH','( dport = :24443 )']).stdout.splitlines();count=sum(bool(pids.intersection(re.findall(r'pid=(\d+)',line))) for line in rows if line.startswith('ESTAB'))
            if count!=2:raise RuntimeError('two independent authenticated TCP carriers not established')
            result.update(success=True,opaque_udp_roundtrip=True,independent_tcp_carriers=count,smux_enabled=False,tls_minimum='1.3',main_stack_modified=False,core_sha256=hashlib.sha256(core.read_bytes()).hexdigest(),engine_sha256=sha)
    except Exception as exc:result.update(error=str(exc))
    finally:
        for unit in reversed(created):subprocess.run(['systemctl','stop',unit],capture_output=True,timeout=20)
        if echo:echo.close()
        result['finished']=time.time();a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
    raise SystemExit(0 if result['success'] else 1)


if __name__=='__main__':main()
