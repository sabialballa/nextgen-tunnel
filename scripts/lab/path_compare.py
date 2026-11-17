#!/usr/bin/env python3
"""Authenticated, bounded direct/site comparison. Test secrets never use argv."""
import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import queue
import re
import socket
import struct
import subprocess
import sys
import threading
import time

def receive(s,n):
    data=b''
    while len(data)<n:
        part=s.recv(n-len(data))
        if not part:raise OSError('EOF')
        data+=part
    return data

def receive_datagram(s,payload,key,started,on_late):
    """Use an absolute application deadline, including scheduling delay."""
    while True:
        remaining=.5-(time.monotonic()-started)
        if remaining<=0:raise socket.timeout()
        s.settimeout(remaining);data=s.recv(2048)
        elapsed=time.monotonic()-started
        if elapsed>.5:
            if data==payload:on_late()
            raise socket.timeout()
        if data==payload:return data
        if len(data)==len(payload) and data[40:]==payload[40:] and hmac.compare_digest(data[:32],hmac.digest(key,data[32:],'sha256')):
            on_late();continue
        return data


def kernel_engine_snapshot(unit):
    """Read process identity without depending on systemd's D-Bus response."""
    group=Path('/sys/fs/cgroup/system.slice')/unit
    found={}
    for pid in (group/'cgroup.procs').read_text().split():
        try:
            proc=Path('/proc')/pid;name=(proc/'exe').resolve().name
            fields=(proc/'stat').read_text().rsplit(') ',1)[1].split()
            if fields[0]=='Z':continue
            if name in ('nextgen-tunnel','sing-box'):found[name]=(pid,fields[19])
        except FileNotFoundError:continue
    if set(found)!= {'nextgen-tunnel','sing-box'}:raise RuntimeError('required engine processes not observed')
    core,child=found['nextgen-tunnel'],found['sing-box']
    return f'KernelSnapshot=1\nMainPID={core[0]}\nEnginePID={child[0]}\nCoreStartTicks={core[1]}\nEngineStartTicks={child[1]}'

def server(a):
    key=a.secret.read_bytes();slots=threading.BoundedSemaphore(8)
    def valid(data):return len(data) in (160,1024) and hmac.compare_digest(data[:32],hmac.digest(key,data[32:],'sha256'))
    def serve(bind,kind):
        s=socket.socket(socket.AF_INET6 if ':' in bind else socket.AF_INET,kind);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        if ':' in bind:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
        s.bind((bind,a.port))
        if kind==socket.SOCK_DGRAM:
            start=time.monotonic();count=0
            while True:
                data,peer=s.recvfrom(2048);now=time.monotonic()
                if now-start>=1:start=now;count=0
                if peer[0] in a.allow and count<100 and valid(data):s.sendto(data,peer);count+=1
        else:
            s.listen(8)
            def echo(c):
                try:
                    with c:
                        c.settimeout(30)
                        while True:
                            data=receive(c,1024)
                            if not valid(data):return
                            c.sendall(data);time.sleep(.01)
                except OSError:pass
                finally:slots.release()
            while True:
                c,peer=s.accept()
                if peer[0] in a.allow and slots.acquire(False):threading.Thread(target=echo,args=(c,),daemon=True).start()
                else:c.close()
    for bind in a.bind:
        for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):threading.Thread(target=serve,args=(bind,kind),daemon=True).start()
    threading.Event().wait()

def worker(a):
    key=bytes.fromhex(sys.stdin.readline().strip());end=time.monotonic()+a.seconds;lock=threading.Lock();flows={};threads=[]
    def flow(peer,protocol):
        name=('ipv6' if ':' in peer else 'ipv4')+'_'+protocol
        state=dict(sent=0,received=0,timeouts=0,reconnects=0,connect_errors=0,corrupted=0,late=0,max_burst=0,rtt_sum_ms=0,rtt_max_ms=0,events=[])
        with lock:flows[name]=state
        seq=0;s=None;burst=0;nonce=os.urandom(8)
        while time.monotonic()<end:
            tick=time.monotonic();event=None
            try:
                if s is None:
                    s=socket.socket(socket.AF_INET6 if ':' in peer else socket.AF_INET,socket.SOCK_STREAM if protocol=='tcp' else socket.SOCK_DGRAM);s.settimeout(3 if protocol=='tcp' else .5)
                    try:s.connect((peer,a.port))
                    except OSError:
                        with lock:state['connect_errors']+=1
                        raise
                body=struct.pack('!Q',seq)+nonce+b'x'*((1024 if protocol=='tcp' else 160)-48);seq+=1;payload=hmac.digest(key,body,'sha256')+body
                with lock:state['sent']+=1
                s.sendall(payload)
                if protocol=='tcp':data=receive(s,1024)
                else:
                    def late():
                        with lock:state['late']+=1
                    data=receive_datagram(s,payload,key,tick,late)
                elapsed=(time.monotonic()-tick)*1000
                if protocol=='udp' and elapsed>500:
                    if data==payload:late()
                    raise socket.timeout()
                with lock:
                    if data!=payload:state['corrupted']+=1;burst+=1;event='corrupted'
                    else:state['received']+=1;state['rtt_sum_ms']+=elapsed;state['rtt_max_ms']=max(state['rtt_max_ms'],elapsed);burst=0
            except OSError as exc:
                event='timeout' if isinstance(exc,TimeoutError) else type(exc).__name__
                with lock:
                    state['timeouts']+=1;burst+=1
                    if protocol=='tcp':state['reconnects']+=1
                if protocol=='tcp' or not isinstance(exc,TimeoutError):
                    if s:s.close()
                    s=None
            with lock:
                state['max_burst']=max(state['max_burst'],burst)
                if event and len(state['events'])<5000:state['events'].append(dict(timestamp=time.time(),kind=event))
            time.sleep(max(0,min((a.tcp_interval if protocol=='tcp' else a.udp_interval)-(time.monotonic()-tick),end-time.monotonic())))
        if s:s.close()
    for peer in a.peer:
        for protocol in ('tcp','udp'):
            t=threading.Thread(target=flow,args=(peer,protocol));t.start();threads.append(t)
    while any(t.is_alive() for t in threads):
        with lock:print(json.dumps(dict(flows=flows,complete=False,timestamp=time.time())),flush=True)
        time.sleep(min(5,max(.1,end-time.monotonic())))
    print(json.dumps(dict(flows=flows,complete=True,timestamp=time.time())),flush=True)

def run(a):
    key=a.secret.read_bytes();messages=queue.Queue();children=[];started=time.monotonic()
    report=dict(started_wall_time=time.time(),seconds_requested=a.seconds,complete=False,paths={},samples=[],sampling_errors=[],measurement_revision=2,udp_deadline_ms=500,udp_interval_seconds=a.udp_interval,tcp_interval_seconds=a.tcp_interval,driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),namespace=a.namespace,engine_unit=a.engine_unit,carrier_tcp_port=a.carrier_tcp_port)
    def read_child(kind,child):
        for line in child.stdout:messages.put((kind,json.loads(line)))
    for kind,peers,port in (('direct',[a.direct_peer],29401),('site',a.peer,21901)):
        command=(['ip','netns','exec',a.namespace] if kind=='site' else [])+['runuser','-u','nobody','--','python3',str(Path(__file__).resolve()),'worker','--seconds',str(a.seconds),'--port',str(port)]
        command+=['--udp-interval',str(a.udp_interval),'--tcp-interval',str(a.tcp_interval)]
        for peer in peers:command+=['--peer',peer]
        child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);child.stdin.write(key.hex()+'\n');child.stdin.close();children.append(child);threading.Thread(target=read_child,args=(kind,child),daemon=True).start()
    next_sample=0
    try:
        while not (len(report['paths'])==2 and all(v['complete'] for v in report['paths'].values())):
            try:
                kind,state=messages.get(timeout=10);report['paths'][kind]=state
            except queue.Empty:
                if any(c.poll() is not None for c in children):raise RuntimeError('worker stopped before final snapshot')
            report['elapsed_seconds']=time.monotonic()-started
            if report['elapsed_seconds']>=next_sample:
                def optional(label,function):
                    try:return function()
                    except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:
                        if len(report['sampling_errors'])<100:report['sampling_errors'].append(dict(timestamp=time.time(),component=label,error=type(exc).__name__))
                        return None
                def output(args):return subprocess.check_output(args,text=True,timeout=5).strip()
                resources={}
                for name,path in (('cpu','/proc/stat'),('pressure_cpu','/proc/pressure/cpu'),('pressure_memory','/proc/pressure/memory'),('pressure_io','/proc/pressure/io')):
                    resources[name]=optional(name,lambda p=path:Path(p).read_text().splitlines()[0])
                def process_usage():
                    result={}
                    for pid in Path('/sys/fs/cgroup/system.slice',a.engine_unit,'cgroup.procs').read_text().split():
                        proc=Path('/proc')/pid
                        try:
                            fields=(proc/'stat').read_text().rsplit(') ',1)[1].split()
                            result[pid]=dict(name=(proc/'exe').resolve().name,utime=int(fields[11]),stime=int(fields[12]),start_ticks=int(fields[19]),rss_pages=int(fields[21]))
                        except FileNotFoundError:continue
                    return dict(clock_ticks=os.sysconf('SC_CLK_TCK'),page_size=os.sysconf('SC_PAGE_SIZE'),cpu_count=os.cpu_count(),processes=result)
                resources['engine_usage']=optional('engine_usage',process_usage)
                report['samples'].append(dict(timestamp=time.time(),engine=optional('engine',lambda:kernel_engine_snapshot(a.engine_unit)),watchdog=None if a.no_watchdog else optional('watchdog',lambda:json.loads(Path('/var/lib/nextgen-stack-watchdog/state.json').read_text())),tcp=optional('tcp',lambda:output(['ss','-tinH',f'( sport = :{a.carrier_tcp_port} or dport = :{a.carrier_tcp_port} or sport = :29401 or dport = :29401 )'])),handshakes=optional('handshakes',lambda:output(['ip','netns','exec',a.namespace,'wg','show','wg0','latest-handshakes'])),resources=resources))
                next_sample=time.monotonic()-started+5
            report['elapsed_seconds']=time.monotonic()-started
            tmp=a.output.with_suffix('.tmp');tmp.write_text(json.dumps(report));tmp.chmod(0o600);tmp.replace(a.output)
        for child in children:
            child.wait(timeout=10)
            if child.returncode:raise RuntimeError('worker exited unsuccessfully')
        report['complete']=True;report['elapsed_seconds']=time.monotonic()-started
    finally:
        for child in children:
            if child.poll() is None:child.terminate();child.wait(timeout=10)
        report['finished_wall_time']=time.time();a.output.write_text(json.dumps(report));a.output.chmod(0o600)
    print(json.dumps(dict(complete=report['complete'],elapsed_seconds=report['elapsed_seconds'])))

def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=('server','worker','run'));p.add_argument('--secret',type=Path);p.add_argument('--allow',action='append',default=[]);p.add_argument('--bind',action='append',default=[]);p.add_argument('--peer',action='append',default=[]);p.add_argument('--port',type=int,default=29401);p.add_argument('--seconds',type=int,default=1800);p.add_argument('--direct-peer');p.add_argument('--output',type=Path)
    p.add_argument('--udp-interval',type=float,default=.1);p.add_argument('--tcp-interval',type=float,default=1)
    p.add_argument('--namespace',default='ngt-site-main');p.add_argument('--engine-unit',default='nextgen-engine.service');p.add_argument('--carrier-tcp-port',type=int,default=443);p.add_argument('--no-watchdog',action='store_true');a=p.parse_args()
    if not .1<=a.udp_interval<=10 or not 1<=a.tcp_interval<=10:p.error('bounded probe intervals required')
    if not re.fullmatch(r'ngt-site-[a-z0-9_-]{1,18}',a.namespace) or not re.fullmatch(r'nextgen-[a-z0-9-]+\.service',a.engine_unit) or not 1<=a.carrier_tcp_port<=65535:p.error('dedicated test namespace/unit and valid carrier port required')
    if not 1<=a.seconds<=3600 or not 1024<=a.port<=65535:p.error('bounded duration/port required')
    {'server':server,'worker':worker,'run':run}[a.action](a)

if __name__=='__main__':main()
