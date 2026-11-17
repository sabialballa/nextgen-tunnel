#!/usr/bin/env python3
"""Real WireGuard routed dual-stack acceptance, only in the owned disposable VM."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

ROOT=Path(__file__).resolve().parents[2]

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if os.geteuid()!=0 or not Path('/etc/nextgen-lab-owned').exists():p.error('marked disposable root VM required')
    report=dict(started=time.time(),checks=[],scope='kernel WireGuard with loopback UDP carrier, routed namespace endpoints');processes=[];stop=threading.Event();enabled=threading.Event();enabled.set();sockets=[]
    def run(label,args,check=True):
        r=subprocess.run([str(v) for v in args],capture_output=True,text=True,timeout=90)
        report['checks'].append(dict(name=label,returncode=r.returncode,stdout=r.stdout,stderr=r.stderr))
        if check and r.returncode:raise RuntimeError(label+': '+r.stderr)
        return r
    route_before=run('routes_before',['ip','-j','route','show']).stdout
    firewall_before=run('firewall_before',['nft','list','ruleset']).stdout
    with tempfile.TemporaryDirectory(prefix='nextgen-site-') as work:
        work=Path(work);names=['ngt-site-lab-a','ngt-site-lab-b'];configs=[]
        try:
            for name in names:run('keygen_'+name,['python3',ROOT/'scripts/site.py','keygen','--directory',work/name])
            for i,name in enumerate(names):
                cfg=dict(name=name,private_key_file=str(work/name/'private.key'),peer_public_key=(work/names[1-i]/'public.key').read_text().strip(),addresses=[f'10.78.0.{i+1}/30',f'fd78::{i+1}/126'],remote_routes=[f'10.78.0.{2-i}/32',f'fd78::{2-i}/128','198.51.100.0/28' if i==0 else '192.0.2.0/28', 'fd79:2::/64' if i==0 else 'fd79:1::/64'],listen_port=51830 if i==0 else 51840,mtu=1280)
                if i==0:cfg['endpoint']='127.0.0.1:51831'
                path=work/(name+'.json');path.write_text(json.dumps(cfg));path.chmod(0o600);configs.append(path)
                run('create_'+name,['python3',ROOT/'scripts/site.py','create','--config',path,'--apply'])
                run('idempotent_'+name,['python3',ROOT/'scripts/site.py','create','--config',path,'--apply'])
                for address in ([('192.0.2.1/32','fd79:1::1/128'),('198.51.100.1/32','fd79:2::1/128')][i]):run('lan_address',['ip','-n',name,'address','add',address,'dev','lo'])
                server_args=['ip','netns','exec',name,'python3',str(ROOT/'scripts/lab/site_probe.py'),'server']
                for address in [f'10.78.0.{i+1}',f'fd78::{i+1}', '192.0.2.1' if i==0 else '198.51.100.1',f'fd79:{i+1}::1']:server_args+=['--listen',address]
                processes.append(subprocess.Popen(server_args,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL))
            front=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);front.bind(('127.0.0.1',51831));back=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);back.connect(('127.0.0.1',51840));sockets.extend([front,back]);peer=[None]
            def pump(source,dest,reverse):
                source.settimeout(.2)
                while not stop.is_set():
                    try:
                        if reverse:
                            data=source.recv(4096)
                            if peer[0] and enabled.is_set():dest.sendto(data,peer[0])
                        else:
                            data,peer[0]=source.recvfrom(4096)
                            if enabled.is_set():dest.send(data)
                    except socket.timeout:pass
                    except OSError:return
            for x,y,reverse in [(front,back,False),(back,front,True)]:threading.Thread(target=pump,args=(x,y,reverse),daemon=True).start()
            for attempt in range(10):
                r=run('handshake_warmup',['ip','netns','exec',names[0],'ping','-c','1','-W','1','10.78.0.2'],False)
                if r.returncode==0:break
            else:raise RuntimeError('WireGuard handshake failed')
            for i,name in enumerate(names):
                peers=['10.78.0.2','fd78::2','198.51.100.1','fd79:2::1'] if i==0 else ['10.78.0.1','fd78::1','192.0.2.1','fd79:1::1']
                args=['ip','netns','exec',name,'python3',ROOT/'scripts/lab/site_probe.py','probe']
                for peer_ip in peers:args+=['--peer',peer_ip]
                run('bidirectional_'+name,args)
            enabled.clear()
            denied=run('carrier_outage',['ip','netns','exec',names[0],'ping','-c','1','-W','2','10.78.0.2'],False)
            if denied.returncode==0:raise RuntimeError('carrier outage did not stop site traffic')
            for name in names:
                routes=json.loads(run('isolated_routes_'+name,['ip','-n',name,'-j','route','show']).stdout)
                if any(route.get('dst')=='default' for route in routes):raise RuntimeError('unexpected underlay default route')
            enabled.set()
            run('carrier_recovery',['ip','netns','exec',names[0],'ping','-c','2','-W','2','10.78.0.2'])
            report['success']=True
        except Exception as exc:report.update(success=False,error=str(exc))
        finally:
            stop.set()
            for proc in processes:proc.terminate()
            for proc in processes:proc.wait(timeout=10)
            for s in sockets:s.close()
            for name in reversed(names):
                run('remove_'+name,['python3',ROOT/'scripts/site.py','remove','--name',name,'--apply'],False)
                run('remove_again_'+name,['python3',ROOT/'scripts/site.py','remove','--name',name,'--apply'],False)
            report['host_routes_unchanged']=route_before==run('routes_after',['ip','-j','route','show']).stdout
            report['host_firewall_unchanged']=firewall_before==run('firewall_after',['nft','list','ruleset']).stdout
            report['success']=report.get('success',False) and report['host_routes_unchanged'] and report['host_firewall_unchanged'] and all(c['returncode']==0 for c in report['checks'] if c['name'].startswith('remove'))
            report['finished']=time.time();a.output.write_text(json.dumps(report,indent=2));print(json.dumps(dict(success=report['success'],output=str(a.output))))
    raise SystemExit(0 if report['success'] else 1)

if __name__=='__main__':main()
