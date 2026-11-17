#!/usr/bin/env python3
"""Real-duration, low-rate bidirectional site soak with bounded telemetry.

Run one host supervisor on each endpoint after reboot acceptance. Workers run
unprivileged inside the site namespace. No credentials or payloads are logged.
"""
import argparse
import collections
import hashlib
import json
import math
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import threading
import time

def atomic(path,value):
    tmp=path.with_suffix('.tmp');tmp.write_text(json.dumps(value,indent=2));tmp.chmod(0o600);tmp.replace(path)

def classify_udp(received,expected):
    if received==expected:return 'current'
    if len(received)==len(expected) and received[8:]==expected[8:]:return 'late'
    return 'invalid'

def worker(a):
    lock=threading.Lock();deadline=time.monotonic()+a.seconds;stats={};threads=[]
    def flow(family,protocol):
        name=('ipv6' if family==socket.AF_INET6 else 'ipv4')+'_'+protocol;peer=a.peer6 if family==socket.AF_INET6 else a.peer4
        state=dict(sent=0,received=0,timeouts=0,corrupted=0,late=0,reconnects=0,connect_errors=0,rtt_sum_ms=0.0,rtt_max_ms=0.0,max_consecutive_failures=0);hist=collections.Counter()
        with lock:stats[name]=(state,hist)
        s=None;sequence=0;consecutive=0;token=os.urandom(8);tick=time.monotonic()
        while time.monotonic()<deadline:
            if s is None:
                try:
                    s=socket.socket(family,socket.SOCK_STREAM if protocol=='tcp' else socket.SOCK_DGRAM);s.settimeout(3 if protocol=='tcp' else .5);s.connect((peer,21901))
                except OSError:
                    with lock:state['connect_errors']+=1
                    if s:s.close()
                    s=None;time.sleep(.5);continue
            payload=struct.pack('!Q',sequence)+token+b'x'*(1008 if protocol=='tcp' else 144);sequence+=1;start=time.monotonic()
            with lock:state['sent']+=1
            try:
                s.sendall(payload)
                if protocol=='tcp':
                    received=b''
                    while len(received)<len(payload):
                        b=s.recv(len(payload)-len(received))
                        if not b:raise OSError('EOF')
                        received+=b
                else:
                    s.settimeout(.5)
                    received=s.recv(2048)
                    while classify_udp(received,payload)=='late':
                        with lock:state['late']+=1
                        remaining=.5-(time.monotonic()-start)
                        if remaining<=0:raise socket.timeout('current UDP response deadline')
                        s.settimeout(remaining)
                        received=s.recv(2048)
                elapsed=(time.monotonic()-start)*1000
                with lock:
                    if received!=payload:state['corrupted']+=1;consecutive+=1
                    else:
                        state['received']+=1;state['rtt_sum_ms']+=elapsed;state['rtt_max_ms']=max(state['rtt_max_ms'],elapsed);hist[min(10000,int(math.ceil(elapsed)))]+=1;consecutive=0
            except OSError:
                with lock:
                    state['timeouts']+=1;consecutive+=1
                    if protocol=='tcp':state['reconnects']+=1
                if protocol=='tcp':s.close();s=None
            with lock:state['max_consecutive_failures']=max(state['max_consecutive_failures'],consecutive)
            tick+=1 if protocol=='tcp' else .1;delay=tick-time.monotonic()
            if delay>0:time.sleep(min(delay,max(0,deadline-time.monotonic())))
            else:tick=time.monotonic()
        if s:s.close()
    for family in (socket.AF_INET,socket.AF_INET6):
        for protocol in ('tcp','udp'):
            t=threading.Thread(target=flow,args=(family,protocol));threads.append(t);t.start()
    def snapshot():
        with lock:
            result={}
            for name,(state,hist) in stats.items():
                r=dict(state);n=r['received'];r['loss_percent']=100*(r['sent']-n)/r['sent'] if r['sent'] else None;r['rtt_mean_ms']=r['rtt_sum_ms']/n if n else None
                for fraction,label in ((.5,'p50'),(.95,'p95'),(.99,'p99')):
                    count=0;r['rtt_'+label+'_ms']=None
                    for bucket,total in sorted(hist.items()):
                        count+=total
                        if count>=max(1,math.ceil(n*fraction)):r['rtt_'+label+'_ms']=bucket;break
                result[name]=r
            return result
    while any(t.is_alive() for t in threads):
        print(json.dumps(dict(flows=snapshot(),complete=False)),flush=True);time.sleep(min(10,max(.1,deadline-time.monotonic())))
    for t in threads:t.join()
    print(json.dumps(dict(flows=snapshot(),complete=True)),flush=True)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--worker',action='store_true');p.add_argument('--seconds',type=int,default=10800);p.add_argument('--peer4',required=True);p.add_argument('--peer6',required=True);p.add_argument('--output',type=Path);p.add_argument('--namespace',default='ngt-site-main');p.add_argument('--engine-unit',default='nextgen-engine.service');a=p.parse_args()
    if not 60<=a.seconds<=86400:p.error('seconds must be 60..86400')
    if a.worker:worker(a);return
    if os.geteuid()!=0 or not a.output:p.error('host supervisor requires root and output')
    if not re.fullmatch(r'ngt-site-[a-z0-9-]{1,18}',a.namespace) or not re.fullmatch(r'nextgen-[a-z0-9-]+\.service',a.engine_unit):p.error('owned namespace/unit required')
    units=(a.engine_unit,'nextgen-site.service','nextgen-site-watchdog.timer') if a.namespace=='ngt-site-main' else (a.engine_unit,)
    def cmd(args):return subprocess.check_output(args,text=True,timeout=15).strip()
    def routes(args):
        # RA lifetimes count down without any change to routing policy.
        entries=json.loads(cmd(args))
        for route in entries:route.pop('expires',None)
        return sorted(entries,key=lambda v:json.dumps(v,sort_keys=True))
    def network():return dict(routes=routes(['ip','-j','route','show']),routes6=routes(['ip','-j','-6','route','show']),firewall=cmd(['nft','list','ruleset']),forwarding=Path('/proc/sys/net/ipv4/ip_forward').read_text())
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();before=network();started=time.monotonic();report=dict(started_wall_time=time.time(),duration_requested_seconds=a.seconds,boot_id=boot,namespace='ngt-site-main',scope='TCP 1 round/s and UDP at most 10 rounds/s per IP family, 1024/160-byte payloads',route_comparison='policy fields; ignores changing IPv6 RA expires countdown only',rtt_percentile_resolution_ms=1,driver_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),binary_sha256={name:hashlib.sha256((Path('/usr/local/lib/nextgen-stack')/name).read_bytes()).hexdigest() for name in ('nextgen-tunnel','sing-box')},acceptance_criteria=dict(tcp_timeouts=0,tcp_reconnects=0,corrupted=0,udp_max_loss_percent=.5,udp_max_consecutive_failures=3,unplanned_engine_pid_changes=0),resource_samples=[],flows={},complete=False)
    report.update(namespace=a.namespace,engine_unit=a.engine_unit)
    process=subprocess.Popen(['ip','netns','exec',a.namespace,'runuser','-u','nobody','--',sys.executable,str(Path(__file__).resolve()),'--worker','--seconds',str(a.seconds),'--peer4',a.peer4,'--peer6',a.peer6],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    next_resource=0;initial_restarts=None;initial_pid=None
    try:
        for line in process.stdout:
            state=json.loads(line);report.update(flows=state['flows'],complete=state['complete'],elapsed_seconds=time.monotonic()-started)
            if report['elapsed_seconds']>=next_resource:
                sample=dict(elapsed_seconds=report['elapsed_seconds'])
                for unit in units:
                    text=cmd(['systemctl','show',unit,'-p','ActiveState','-p','MainPID','-p','NRestarts','-p','MemoryCurrent','-p','CPUUsageNSec']);sample[unit]=dict(v.split('=',1) for v in text.splitlines() if '=' in v)
                if initial_restarts is None:initial_restarts=sample[a.engine_unit]['NRestarts'];initial_pid=sample[a.engine_unit]['MainPID']
                report['resource_samples'].append(sample);next_resource+=60
            atomic(a.output,report)
        process.wait(timeout=10)
        if process.returncode:raise RuntimeError('worker failed: '+process.stderr.read()[-1000:])
        report['elapsed_seconds']=time.monotonic()-started;report['network_unchanged']=before==network();report['boot_unchanged']=boot==Path('/proc/sys/kernel/random/boot_id').read_text().strip()
        stable=all(s[u]['ActiveState']=='active' for s in report['resource_samples'] for u in units) and all(s[a.engine_unit]['NRestarts']==initial_restarts and s[a.engine_unit]['MainPID']==initial_pid for s in report['resource_samples'])
        flows_ok=len(report['flows'])==4 and all(v['received']>0 and v['corrupted']==0 and v['connect_errors']==0 and (v['timeouts']==0 and v['reconnects']==0 if name.endswith('tcp') else v['loss_percent']<=.5 and v['max_consecutive_failures']<=3) for name,v in report['flows'].items())
        report['success']=report['complete'] and report['elapsed_seconds']>=a.seconds and report['network_unchanged'] and report['boot_unchanged'] and stable and flows_ok
    except Exception as exc:report.update(success=False,error=str(exc))
    finally:
        if process.poll() is None:process.terminate();process.wait(timeout=10)
        report['finished_wall_time']=time.time();atomic(a.output,report)
    print(json.dumps(dict(success=report.get('success',False),elapsed_seconds=report.get('elapsed_seconds'),output=str(a.output))));raise SystemExit(0 if report.get('success') else 1)

if __name__=='__main__':main()
