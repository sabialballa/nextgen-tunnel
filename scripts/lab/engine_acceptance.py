#!/usr/bin/env python3
"""Real Hysteria2/REALITY + isolated dual-stack TUN acceptance in disposable VM."""
import argparse
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[2]
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--engine',type=Path,required=True);p.add_argument('--sha256',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if os.geteuid()!=0 or not Path('/etc/nextgen-lab-owned').exists():p.error('marked disposable root VM required')
    report=dict(started=time.time(),checks=[],engine_sha256=a.sha256);processes=[];logs=[];servers=[];stop=threading.Event();work=Path('/var/lib')/('nextgen-engine-lab-'+str(time.time_ns()))
    binary=ROOT/'bin/nextgen-tunnel'
    def cmd(label,args,check=True):
        r=subprocess.run([str(x) for x in args],capture_output=True,text=True,timeout=90)
        report['checks'].append(dict(name=label,returncode=r.returncode,stdout=r.stdout,stderr=r.stderr));print(label,r.returncode,flush=True)
        if check and r.returncode:raise RuntimeError(label+': '+r.stderr[-1000:])
        return r
    def launch(label,args):
        log=open(work/(label+'.log'),'wb');logs.append(log);proc=subprocess.Popen([str(x) for x in args],stdout=log,stderr=log);processes.append(proc);return proc
    def run_config(label,path):return launch(label,[binary,'engine-run','-binary',a.engine,'-sha256',a.sha256,'-config',path])
    def app(label):
        code='''import socket,urllib.request
for host in ("198.18.10.1","fd00:198::1"):
 url="http://"+("["+host+"]" if ":" in host else host)+":19803/"
 assert urllib.request.urlopen(url,timeout=15).status==204
 family=socket.AF_INET6 if ":" in host else socket.AF_INET
 with socket.socket(family,socket.SOCK_DGRAM) as s:
  s.settimeout(15);s.connect((host,19804));b=b"UDP-through-TUN"*50;s.send(b);assert s.recv(65535)==b
print("IPv4/IPv6 TCP and UDP passed")
'''
        return cmd(label,['ip','netns','exec','ngt-apps','python3','-c',code],check=False)
    def wait_app(label,seconds=45):
        end=time.monotonic()+seconds
        while time.monotonic()<end:
            result=app(label)
            if result.returncode==0:return
            time.sleep(2)
        raise RuntimeError(label+' did not recover')
    def namespace_links():return json.loads(cmd('namespace_links',['ip','-n','ngt-apps','-j','link','show']).stdout)
    try:
        if hashlib.sha256(a.engine.read_bytes()).hexdigest()!=a.sha256:raise RuntimeError('engine integrity mismatch')
        if not work.exists():cmd('engine_init',[binary,'engine-init','-dir',work,'-server-ip','127.0.0.1'])
        profile=json.loads((work/'profile.json').read_text());profile.update(dns_server='198.18.10.1',health_url='http://198.18.10.1:19803/',allow_cidrs=['198.18.10.0/24','fd00:198::/64'])
        (work/'profile.json').write_text(json.dumps(profile))
        out=work/'configs';cmd('engine_plan',[binary,'engine-plan','-profile',work/'profile.json','-output',out])
        for role in ('server','client'):cmd('check_'+role,[binary,'engine-check','-binary',a.engine,'-sha256',a.sha256,'-config',out/(role+'.json')])
        cmd('namespace_create',[sys.executable,ROOT/'scripts/namespace.py','create','--apply']);cmd('namespace_idempotent',[sys.executable,ROOT/'scripts/namespace.py','create','--apply'])
        cmd('lab_ipv4',['ip','addr','add','198.18.10.1/32','dev','lo']);cmd('lab_ipv6',['ip','-6','addr','add','fd00:198::1/128','dev','lo'])
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):self.send_response(204);self.end_headers()
            def log_message(self,*args):pass
        class HTTP6(http.server.ThreadingHTTPServer):address_family=socket.AF_INET6
        for klass,host,port in ((http.server.ThreadingHTTPServer,'198.18.10.1',19803),(HTTP6,'fd00:198::1',19803),(http.server.ThreadingHTTPServer,'127.0.0.1',19443)):
            server=klass((host,port),Handler)
            if port==19443:
                ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_3;ctx.load_cert_chain(profile['cert'],profile['key']);server.socket=ctx.wrap_socket(server.socket,server_side=True)
            servers.append(server);threading.Thread(target=server.serve_forever,daemon=True).start()
        udp_sockets=[]
        for family,host in ((socket.AF_INET,'198.18.10.1'),(socket.AF_INET6,'fd00:198::1')):
            sock=socket.socket(family,socket.SOCK_DGRAM);sock.bind((host,19804));sock.settimeout(.2);udp_sockets.append(sock)
            def echo(s):
                while not stop.is_set():
                    try:b,addr=s.recvfrom(65535);s.sendto(b,addr)
                    except socket.timeout:continue
                    except OSError:return
            threading.Thread(target=echo,args=(sock,),daemon=True).start()
        dns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);dns.bind(('198.18.10.1',53));dns.settimeout(.2);udp_sockets.append(dns)
        def dns_loop():
            while not stop.is_set():
                try:
                    b,addr=dns.recvfrom(4096);end=12
                    while b[end]:end+=b[end]+1
                    end+=1;qtype=struct.unpack('!H',b[end:end+2])[0];question=b[12:end+4]
                    data=socket.inet_pton(socket.AF_INET6,'fd00:198::1') if qtype==28 else socket.inet_aton('198.18.10.1')
                    answer=b'\xc0\x0c'+struct.pack('!HHIH',qtype,1,60,len(data))+data
                    dns.sendto(b[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+question+answer,addr)
                except socket.timeout:continue
                except OSError:return
        threading.Thread(target=dns_loop,daemon=True).start()
        server_config=json.loads((out/'server.json').read_text())
        server_procs={}
        for index,label in enumerate(('hy2','reality')):
            cfg=dict(server_config,inbounds=[server_config['inbounds'][index]]);path=work/(label+'-server.json');path.write_text(json.dumps(cfg));path.chmod(0o600);server_procs[label]=run_config(label+'-server',path)
        base=json.loads((out/'client.json').read_text())
        for label in ('hy2','reality'):
            config=dict(base,outbounds=[dict(type='selector',tag='auto',outbounds=['hy2','reality'],default=label),*base['outbounds'][1:]])
            path=work/(label+'-client.json');path.write_text(json.dumps(config));path.chmod(0o600);client=run_config(label+'-client',path)
            wait_app(label+'_dual_stack')
            cmd(label+'_dns',['ip','netns','exec','ngt-apps','python3','-c','import socket; assert socket.gethostbyname("probe.example.test")=="198.18.10.1"; print("proxied DNS passed")'])
            client.terminate();client.wait(timeout=15);time.sleep(1)
        client=run_config('adaptive-client',out/'client.json');wait_app('adaptive_initial')
        server_procs['hy2'].terminate();server_procs['hy2'].wait(timeout=15);start=time.monotonic();wait_app('adaptive_udp_outage',seconds=75);report['new_flows_after_udp_outage_seconds']=time.monotonic()-start
        client.terminate();client.wait(timeout=15);time.sleep(1)
        links=namespace_links();assert [v['ifname'] for v in links]==['lo']
        denied=cmd('fail_closed_after_engine_exit',['ip','netns','exec','ngt-apps','python3','-c','import socket; s=socket.socket(); s.settimeout(2); s.connect(("198.18.10.1",19803))'],check=False)
        assert denied.returncode!=0;report['kill_switch_no_underlay']=True
        cmd('namespace_remove',[sys.executable,ROOT/'scripts/namespace.py','remove','--apply']);cmd('namespace_remove_idempotent',[sys.executable,ROOT/'scripts/namespace.py','remove','--apply'])
        report['success']=True
    except BaseException as exc:
        report['success']=False;report['error']=str(exc);raise
    finally:
        for proc in processes:
            if proc.poll() is None:proc.terminate();proc.wait(timeout=15)
        for f in logs:f.close()
        for s in servers:s.shutdown();s.server_close()
        stop.set()
        for sock in locals().get('udp_sockets',[]):sock.close()
        subprocess.run(['ip','addr','del','198.18.10.1/32','dev','lo'],capture_output=True);subprocess.run(['ip','-6','addr','del','fd00:198::1/128','dev','lo'],capture_output=True)
        if work.exists():report['logs']={f.name:f.read_text(errors='replace') for f in work.glob('*.log')}
        report['finished']=time.time();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2))
if __name__=='__main__':main()
