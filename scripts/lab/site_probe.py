#!/usr/bin/env python3
"""Dual-stack TCP/UDP payload checks inside a dedicated site namespace."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import threading
import time

def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=('server','probe'));p.add_argument('--peer',action='append',default=[]);p.add_argument('--listen',action='append',default=[]);p.add_argument('--rounds',type=int,default=20);p.add_argument('--output',type=Path);a=p.parse_args()
    if not 1<=a.rounds<=5000:p.error('rounds must be 1..5000')
    if a.action=='server':
        def serve(address,kind):
            family=socket.AF_INET6 if ':' in address else socket.AF_INET
            s=socket.socket(family,kind);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            s.bind((address,21901))
            if kind==socket.SOCK_DGRAM:
                while True:
                    b,addr=s.recvfrom(2048);s.sendto(b,addr)
            else:
                s.listen(8)
                slots=threading.BoundedSemaphore(16)
                def echo(c):
                    try:
                        with c:
                            c.settimeout(30)
                            while True:
                                b=c.recv(4096)
                                if not b:break
                                c.sendall(b)
                    except OSError:pass
                    finally:slots.release()
                while True:
                    c,_=s.accept()
                    if slots.acquire(blocking=False):threading.Thread(target=echo,args=(c,),daemon=True).start()
                    else:c.close()
        for address in a.listen or ['0.0.0.0','::']:
            for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):threading.Thread(target=serve,args=(address,kind),daemon=True).start()
        threading.Event().wait();return
    report=dict(started=time.time(),checks=[])
    for peer in a.peer:
        for protocol,kind in [('tcp',socket.SOCK_STREAM),('udp',socket.SOCK_DGRAM)]:
            r=dict(peer=peer,protocol=protocol,success=False);s=socket.socket(socket.AF_INET6 if ':' in peer else socket.AF_INET,kind);s.settimeout(8)
            try:
                s.connect((peer,21901));times=[]
                for i in range(a.rounds):
                    payload=hashlib.sha256(str(i).encode()).digest()*32;start=time.monotonic();s.sendall(payload);received=b''
                    while len(received)<len(payload):
                        b=s.recv(2048)
                        if not b:raise RuntimeError('unexpected EOF')
                        received+=b
                    if received!=payload:raise RuntimeError('payload mismatch')
                    times.append((time.monotonic()-start)*1000)
                r.update(success=True,rounds=a.rounds,payload_bytes=1024,rtt_min_ms=min(times),rtt_mean_ms=sum(times)/len(times),rtt_max_ms=max(times))
            except Exception as e:r['error']=str(e)
            finally:s.close()
            report['checks'].append(r)
    report.update(finished=time.time(),success=all(c['success'] for c in report['checks']) and bool(report['checks']))
    if a.output:a.output.write_text(json.dumps(report,indent=2))
    print(json.dumps(report));raise SystemExit(0 if report['success'] else 1)

if __name__=='__main__':main()
