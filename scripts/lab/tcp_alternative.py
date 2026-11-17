#!/usr/bin/env python3
"""Prepare a temporary, bounded Trojan/TLS1.3 carrier with no smux.

Credentials are read from files, never command arguments or environment.
The established main stack is neither read for secrets nor modified.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets

UNIT='/run/credentials/nextgen-alt-engine.service/'
IDENTITY='ngt-alt.example.invalid'


def profiles(server,password):
    ipaddress.ip_address(server)
    inbound=dict(type='trojan',tag='alt-tls',listen='0.0.0.0',listen_port=24443,users=[dict(name='site-alt',password=password)],tls=dict(enabled=True,min_version='1.3',certificate_path=UNIT+'cert',key_path=UNIT+'key',client_authentication='require-and-verify',client_certificate_path=UNIT+'ca'))
    listener=dict(log=dict(level='warn'),inbounds=[inbound],outbounds=[dict(type='direct',tag='site-egress')],route=dict(rules=[dict(ip_cidr=['127.0.0.1/32'],port=[52851],action='route',outbound='site-egress'),dict(action='reject')]))
    inbounds=[];outbounds=[];rules=[]
    for i in range(2):
        tag='alt-'+str(i);carrier='alt-carrier-'+str(i)
        inbounds.append(dict(type='direct',tag=tag,listen='127.0.0.1',listen_port=52812+i,network='udp',override_address='127.0.0.1',override_port=52851))
        outbounds.append(dict(type='trojan',tag=carrier,server=server,server_port=24443,password=password,tls=dict(enabled=True,min_version='1.3',server_name=IDENTITY,certificate_path=UNIT+'ca',client_certificate_path=UNIT+'cert',client_key_path=UNIT+'key')))
        rules.append(dict(inbound=[tag],action='route',outbound=carrier))
    initiator=dict(log=dict(level='warn'),inbounds=inbounds,outbounds=outbounds,route=dict(rules=rules,final='alt-carrier-0'))
    return listener,initiator


def write_new(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as f:json.dump(value,f,indent=2);f.write('\n')


def main():
    p=argparse.ArgumentParser();p.add_argument('--role',choices=('listener','initiator'),required=True);p.add_argument('--directory',type=Path,required=True);p.add_argument('--server',required=True);p.add_argument('--peer-key-file',type=Path,required=True);a=p.parse_args()
    d=a.directory
    if not d.is_absolute() or d.is_symlink() or not d.is_dir() or d.stat().st_uid!=0 or d.stat().st_mode&0o077:p.error('existing protected root test directory required')
    peer=a.peer_key_file.read_text().strip();import base64
    if len(base64.b64decode(peer,validate=True))!=32:p.error('WireGuard public key required')
    if a.role=='listener':
        server,client=profiles(a.server,secrets.token_hex(32));write_new(d/'engine.json',server);write_new(d/'client-export.json',client)
        relay=dict(enabled=True,mode='listener',listen='127.0.0.1:52851',target='127.0.0.1:52850');local='1';remote='2';port=52850
    else:
        client=json.loads((d/'client-export.json').read_text());write_new(d/'engine.json',client)
        relay=dict(enabled=True,listen='127.0.0.1:52811',target='127.0.0.1:52860',backends=['127.0.0.1:52812','127.0.0.1:52813']);local='2';remote='1';port=52860
    site=dict(name='ngt-site-alt',private_key_file=str(d/'wg/private.key'),peer_public_key=peer,addresses=['10.77.241.'+local+'/30','fd77:241::'+local+'/126'],remote_routes=['10.77.241.'+remote+'/32','fd77:241::'+remote+'/128'],listen_port=port,mtu=1280,persistent_keepalive=1)
    if a.role=='initiator':site['endpoint']='127.0.0.1:52811'
    write_new(d/'site.json',site);write_new(d/'relay.json',relay)
    print('Created protected temporary alternative profile; validate before starting')


if __name__=='__main__':main()
