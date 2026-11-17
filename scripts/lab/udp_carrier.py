#!/usr/bin/env python3
"""Loopback-only single-peer UDP relay for the encrypted WireGuard baseline.

This supplies no encryption or DPI protection itself. Use only with WireGuard.
"""
import argparse
import ipaddress
import socket
import threading

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--peer',required=True);p.add_argument('--peer-port',type=int,required=True);p.add_argument('--listen-port',type=int,default=51811);a=p.parse_args()
    ipaddress.IPv4Address(a.peer)
    if not all(1024<=port<=65535 for port in (a.peer_port,a.listen_port)):p.error('unprivileged valid ports required')
    front=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);front.bind(('127.0.0.1',a.listen_port));back=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);back.connect((a.peer,a.peer_port));peer=[None]
    def replies():
        while True:
            data=back.recv(4096)
            if peer[0]:front.sendto(data,peer[0])
    threading.Thread(target=replies,daemon=True).start()
    while True:
        data,addr=front.recvfrom(4096)
        if peer[0] is None:peer[0]=addr
        if addr==peer[0]:back.send(data)

if __name__=='__main__':main()
