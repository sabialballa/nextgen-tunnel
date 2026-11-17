#!/usr/bin/env python3
"""Derive a bounded carrier from a protected engine-plan JSON.

Run separately on each endpoint. This never copies listener/CA private keys to
the initiating endpoint and never writes to the installed stack.
"""
import argparse
import copy
import ipaddress
import json
import os
from pathlib import Path

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--role',choices=('listener','initiator'),required=True)
    p.add_argument('--transport',choices=('reality-smux','hysteria2-gecko'),default='reality-smux')
    p.add_argument('--redundant',action='store_true',help='bounded independent REALITY carriers with a reverse fanout listener')
    p.add_argument('--carriers',type=int,choices=(2,3,4),default=2,help='independent streams; four is experimental and did not establish field stability')
    p.add_argument('--source',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--remote-wg-port',type=int,default=51850)
    p.add_argument('--carrier-port',type=int,default=51811)
    p.add_argument('--public-port',type=int,default=443)
    a=p.parse_args()
    if a.redundant and a.transport!='reality-smux':p.error('redundancy requires REALITY/smux')
    if a.redundant and a.remote_wg_port==65535:p.error('room for listener relay port required')
    if a.redundant and a.role=='initiator' and a.carrier_port>65535-a.carriers:p.error('room for backend ports required')
    if any(not 1024<=v<=65535 for v in (a.remote_wg_port,a.carrier_port)) or not 1<=a.public_port<=65535:p.error('invalid port')
    if a.output.exists() or a.output.is_symlink():p.error('output must be a new path')
    cfg=json.loads(a.source.read_text());key='inbounds' if a.role=='listener' else 'outbounds'
    transport='vless' if a.transport=='reality-smux' else 'hysteria2'
    matches=[x for x in cfg[key] if x['type']==transport]
    if len(matches)!=1:p.error('exactly one selected transport required')
    hy=copy.deepcopy(matches[0]);hy['tag']='carrier'
    if not hy.get('tls',{}).get('enabled') or hy['tls'].get('insecure'):p.error('verified TLS required')
    if transport=='hysteria2':
        secret=hy['users'][0]['password'] if a.role=='listener' else hy['password']
        if len(secret)<32:p.error('strong generated authentication required')
        hy.update(obfs=dict(type='gecko',password=secret),disable_path_mtu_discovery=True,initial_packet_size=1200)
    else:
        if not hy['tls'].get('reality',{}).get('enabled'):p.error('REALITY required')
        hy['multiplex']=dict(enabled=True,padding=True)
        if a.role=='listener':
            for user in hy['users']:user['flow']=''
            target=hy['tls']['reality']['handshake']['server']
            if ipaddress.ip_address(target).is_loopback:p.error('replace the laboratory REALITY target with a verified compatible literal TLS target')
        else:
            hy['flow']='';hy['packet_encoding']='';hy['multiplex'].update(protocol='smux',max_connections=4,min_streams=1)
    out=dict(log=dict(level='warn'))
    destination_port=a.remote_wg_port+(1 if a.redundant else 0)
    if a.role=='listener':
        hy['listen']='0.0.0.0';hy['listen_port']=a.public_port
        out.update(inbounds=[hy],outbounds=[dict(type='direct',tag='site-egress')],route=dict(rules=[dict(ip_cidr=['127.0.0.1/32'],port=[destination_port],action='route',outbound='site-egress'),dict(action='reject')]))
    else:
        ipaddress.ip_address(hy['server']);hy['server_port']=a.public_port
        out.update(inbounds=[dict(type='direct',tag='site',listen='127.0.0.1',listen_port=a.carrier_port,network='udp',override_address='127.0.0.1',override_port=destination_port)],outbounds=[hy],route=dict(final='carrier'))
    if a.redundant and a.role=='initiator':
        inbounds=[];outbounds=[];rules=[]
        for index in range(a.carriers):
            inbound=copy.deepcopy(out['inbounds'][0]);inbound['tag']=f'site-{index}';inbound['listen_port']=a.carrier_port+index+1
            outbound=copy.deepcopy(hy);outbound['tag']=f'carrier-{index}';outbound['multiplex']['max_connections']=1
            inbounds.append(inbound);outbounds.append(outbound);rules.append(dict(inbound=[inbound['tag']],action='route',outbound=outbound['tag']))
        out.update(inbounds=inbounds,outbounds=outbounds,route=dict(rules=rules,final='carrier-0'))
    fd=os.open(a.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'w') as handle:json.dump(out,handle,indent=2);handle.write('\n')
    print('created private carrier configuration; run engine-check and data-plane acceptance before deployment')
    if a.redundant and a.role=='listener':print(f'set listener site JSON redundant_listener_port to {destination_port}')

if __name__=='__main__':main()
