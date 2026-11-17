#!/usr/bin/env python3
"""Index encrypted WireGuard header captures; never export packet contents/IPs."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import struct


def index(path,port):
    raw=path.read_bytes()
    if len(raw)>32*1024*1024 or len(raw)<24:raise ValueError('bounded pcap required')
    formats={b'\xd4\xc3\xb2\xa1':('<',1e6),b'\xa1\xb2\xc3\xd4':('>',1e6),b'\x4d\x3c\xb2\xa1':('<',1e9),b'\xa1\xb2\x3c\x4d':('>',1e9)}
    endian,scale=formats[raw[:4]]
    _,_,_,_,snap,link=struct.unpack(endian+'HHiiii',raw[4:24])
    if link!=1 or not 106<=snap<=256:raise ValueError('Ethernet header capture required')
    pos=24;rows={};times=[]
    while pos<len(raw):
        if len(raw)-pos<16:raise ValueError('truncated record header')
        sec,sub,cap,original=struct.unpack(endian+'IIII',raw[pos:pos+16]);pos+=16
        if cap>snap or cap>original or pos+cap>len(raw):raise ValueError('truncated/invalid capture')
        packet=raw[pos:pos+cap];pos+=cap;ts=sec+sub/scale;times.append(ts)
        if len(packet)<42 or packet[12:14]!=b'\x08\x00' or packet[14]>>4!=4 or packet[23]!=17:continue
        udp=14+(packet[14]&15)*4
        if len(packet)<udp+8:continue
        source,destination,length=struct.unpack('!HHH',packet[udp:udp+6]);n=length-8
        if n<4 or len(packet)<udp+8+min(64,n):continue
        payload=packet[udp+8:udp+8+min(64,n)]
        if int.from_bytes(payload[:4],'little') not in (1,2,3,4):continue
        direction='sent' if source==port else 'received' if destination==port else None
        if direction is None:continue
        digest=hashlib.sha256(struct.pack('!I',n)+payload).hexdigest()
        row=rows.setdefault(digest,{})
        row[direction]=min(row.get(direction,ts),ts)
    if not times:raise ValueError('empty capture')
    return dict(raw_sha256=hashlib.sha256(raw).hexdigest(),start=min(times),end=max(times),rows=rows)


def main():
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--port',type=int,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    r=index(a.input,a.port);a.output.write_bytes(gzip.compress(json.dumps(r).encode(),mtime=0));a.output.chmod(0o600)
    print(json.dumps(dict(unique_datagrams=len(r['rows']),seconds=r['end']-r['start'],raw_sha256=r['raw_sha256'])))


if __name__=='__main__':main()
