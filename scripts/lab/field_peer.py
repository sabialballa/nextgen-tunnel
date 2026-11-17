#!/usr/bin/env python3
"""Bounded field echo baseline and encrypted-path measurements. No host tuning."""
import argparse
import concurrent.futures
import hashlib
import http.server
import json
from pathlib import Path
import signal
import socket
import statistics
import struct
import threading
import time

def tcp_echo(listener,peer=None):
    slots=threading.BoundedSemaphore(16)
    def one(c):
        try:
            c.settimeout(30)
            with c:
                while True:
                    b=c.recv(65536)
                    if not b:return
                    c.sendall(b)
        except OSError:pass
        finally:slots.release()
    while True:
        c,addr=listener.accept()
        if (peer and addr[0]!=peer) or not slots.acquire(blocking=False):c.close();continue
        threading.Thread(target=one,args=(c,),daemon=True).start()

def udp_echo(s,peer=None):
    while True:
        b,addr=s.recvfrom(4096)
        if len(b)<=2048 and (not peer or addr[0]==peer):s.sendto(b,addr)

def server(peer):
    for network,host,port,restrict in [('tcp','0.0.0.0',21100,peer),('udp','0.0.0.0',21100,peer),('tcp','127.0.0.1',19801,None),('udp','127.0.0.1',19802,None)]:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM if network=='tcp' else socket.SOCK_DGRAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind((host,port))
        if network=='tcp':s.listen(16)
        threading.Thread(target=tcp_echo if network=='tcp' else udp_echo,args=(s,restrict),daemon=True).start()
    class Health(http.server.BaseHTTPRequestHandler):
        def do_GET(self):self.send_response(204);self.end_headers()
        def log_message(self,*args):pass
    http.server.ThreadingHTTPServer(('127.0.0.1',19803),Health).serve_forever()

def percentile(values,p):
    v=sorted(values);return v[min(len(v)-1,int((len(v)-1)*p))] if v else None

def tcp_measure(address,seconds,rate):
    begin=time.monotonic();s=socket.create_connection(address,timeout=8);s.settimeout(10);nonce=b'field-setup-v1';s.sendall(nonce)
    setup=bytearray()
    while len(setup)<len(nonce):
        b=s.recv(len(nonce)-len(setup))
        if not b:raise RuntimeError('setup EOF')
        setup.extend(b)
    if bytes(setup)!=nonce:raise RuntimeError('setup corruption')
    setup_ms=(time.monotonic()-begin)*1000
    payload=bytes(range(256))*128;received=0;rh=hashlib.sha256();failure=[]
    def reader():
        nonlocal received
        try:
            while True:
                b=s.recv(65536)
                if not b:return
                rh.update(b);received+=len(b)
        except Exception as e:failure.append(str(e))
    thread=threading.Thread(target=reader);thread.start();start=time.monotonic();sent=0;sh=hashlib.sha256()
    try:
        while time.monotonic()-start<seconds:
            s.sendall(payload);sh.update(payload);sent+=len(payload);delay=start+sent*8/(rate*1e6)-time.monotonic()
            if delay>0:time.sleep(delay)
        s.shutdown(socket.SHUT_WR);thread.join(timeout=12)
        if thread.is_alive():raise RuntimeError('echo drain deadline')
    finally:s.close();thread.join(timeout=2)
    elapsed=time.monotonic()-start
    if failure or sent!=received or sh.digest()!=rh.digest():raise RuntimeError('stream mismatch or receive failure '+str(failure))
    return dict(sent=sent,received=received,elapsed_seconds=elapsed,echo_payload_mbit_s=received*8/elapsed/1e6,configured_mbit_s=rate,connection_and_first_response_ms=setup_ms)

def udp_measure(address,seconds,rate):
    s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect(address);s.settimeout(5);warm=time.monotonic();nonce=b'UDP-warmup-v1';s.send(nonce)
    if s.recv(4096)!=nonce:raise RuntimeError('UDP warmup failed')
    warm_ms=(time.monotonic()-warm)*1000;s.settimeout(.2);stop=threading.Event();seen=set();rtts=[];reordered=0;duplicates=0;highest=-1;bad=0
    def receiver():
        nonlocal reordered,duplicates,highest,bad
        while not stop.is_set():
            try:b=s.recv(4096)
            except socket.timeout:continue
            except OSError:return
            if len(b)!=160 or b[16:]!=b'x'*144:bad+=1;continue
            seq,stamp=struct.unpack('!QQ',b[:16]);rtts.append((time.monotonic_ns()-stamp)/1e6)
            if seq in seen:duplicates+=1;continue
            if seq<highest:reordered+=1
            highest=max(highest,seq);seen.add(seq)
    thread=threading.Thread(target=receiver);thread.start();start=time.monotonic();sent=0
    try:
        while time.monotonic()-start<seconds:
            s.send(struct.pack('!QQ',sent,time.monotonic_ns())+b'x'*144);sent+=1;delay=start+sent*160*8/(rate*1e6)-time.monotonic()
            if delay>0:time.sleep(delay)
        time.sleep(2)
    finally:stop.set();s.close();thread.join(timeout=2)
    return dict(sent=sent,received=len(seen),lost=sent-len(seen),loss_percent=100*(sent-len(seen))/sent,reordered=reordered,duplicates=duplicates,corrupted=bad,rate_mbit_s=rate,seconds=seconds,warmup_rtt_ms=warm_ms,rtt_avg_ms=statistics.mean(rtts) if rtts else None,rtt_p50_ms=percentile(rtts,.5),rtt_p95_ms=percentile(rtts,.95),rtt_p99_ms=percentile(rtts,.99),adjacent_rtt_difference_mean_ms=statistics.mean(abs(a-b) for a,b in zip(rtts,rtts[1:])) if len(rtts)>1 else None)

def main():
    p=argparse.ArgumentParser(description=__doc__);sp=p.add_subparsers(dest='action',required=True);s=sp.add_parser('server');s.add_argument('--peer',required=True)
    c=sp.add_parser('measure');c.add_argument('--host',required=True);c.add_argument('--tcp-port',type=int,required=True);c.add_argument('--udp-port',type=int,required=True);c.add_argument('--label',required=True);c.add_argument('--seconds',type=int,default=20);c.add_argument('--tcp-rate',type=float,default=5);c.add_argument('--udp-rate',type=float,default=1);c.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    if a.action=='server':socket.inet_aton(a.peer);server(a.peer);return
    if not 5<=a.seconds<=120:p.error('seconds must be 5..120')
    if not .01<=a.tcp_rate<=10 or not .01<=a.udp_rate<=2:p.error('TCP rate must be .01..10 Mbps and UDP .01..2 Mbps')
    result=dict(label=a.label,started=time.time(),scope='fixed-rate bidirectional payload echo; completion is not production acceptance or maximum capacity',tcp_offered_mbit_s=a.tcp_rate,udp_offered_mbit_s=a.udp_rate)
    errors={}
    def record(name,operation):
        try:result[name]=operation()
        except Exception as exc:errors[name]=str(exc)
    record('tcp_single',lambda:tcp_measure((a.host,a.tcp_port),a.seconds,a.tcp_rate))
    def four():
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:return list(pool.map(lambda _:tcp_measure((a.host,a.tcp_port),a.seconds,a.tcp_rate/4),range(4)))
    record('tcp_four',four)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        load=pool.submit(tcp_measure,(a.host,a.tcp_port),a.seconds,a.tcp_rate)
        record('udp_under_tcp_load',lambda:udp_measure((a.host,a.udp_port),a.seconds,a.udp_rate))
        record('tcp_during_udp',load.result)
    result.update(success=not errors,errors=errors,finished=time.time());a.output.write_text(json.dumps(result,indent=2));print(json.dumps(dict(label=a.label,success=result['success'],output=str(a.output))))
    if not result['success']:raise SystemExit(1)
if __name__=='__main__':main()
