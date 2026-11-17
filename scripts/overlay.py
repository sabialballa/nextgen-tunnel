#!/usr/bin/env python3
"""Owned IPv4 GRE/VXLAN overlays inside an existing TCP-backed site namespace.

Never creates public GRE/UDP paths, bridges host interfaces, or changes host routes.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import subprocess

STATE=Path('/var/lib/nextgen-overlays')
def run(args):return subprocess.check_output(args,text=True,timeout=20).strip()
def validate(c):
 if set(c)-{'name','namespace','kind','local','remote','address','mtu','vni','port'}:raise ValueError('unknown overlay option')
 if not re.fullmatch(r'ngo-[a-z0-9-]{1,11}',c['name']) or not re.fullmatch(r'ngt-site-[a-z0-9_-]{1,18}',c['namespace']):raise ValueError('dedicated link and namespace required')
 if c['kind'] not in ('gre','vxlan','ipip'):raise ValueError('GRE, VXLAN or IPIP required')
 local=ipaddress.IPv4Address(c['local']);remote=ipaddress.IPv4Address(c['remote']);address=ipaddress.IPv4Interface(c['address'])
 if any(not v.is_private or v.is_loopback or v.is_multicast or v.is_unspecified or v.is_link_local for v in (local,remote,address.ip)) or local==remote:raise ValueError('distinct private site IPv4 endpoints required')
 if address.network.prefixlen not in (30,31) or (address.network.prefixlen==30 and address.ip in (address.network.network_address,address.network.broadcast_address)):raise ValueError('usable point-to-point /30 or /31 required')
 if local in address.network or remote in address.network:raise ValueError('overlay must not overlap its underlay')
 if type(c.get('mtu'))!=int or not 576<=c['mtu']<=1400:raise ValueError('explicit IPv4 MTU required')
 if c['kind']=='vxlan':
  if type(c.get('vni'))!=int or not 1<=c['vni']<=16777215 or type(c.get('port'))!=int or not 1024<=c['port']<=65535:raise ValueError('explicit VNI and unprivileged destination port required')
 elif 'vni' in c or 'port' in c:raise ValueError('VXLAN options on GRE')
 return c
def protected(p):
 if p.is_symlink() or not p.is_dir() or p.stat().st_uid!=0 or p.stat().st_mode&0o022:raise ValueError('unsafe state directory')
def main():
 import fcntl
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=['create','status','remove']);p.add_argument('--config',type=Path,required=True);p.add_argument('--apply',action='store_true');a=p.parse_args()
 c=validate(json.loads(a.config.read_text()));name=c['name'];ns=c['namespace']
 if a.action!='status' and not a.apply:print(json.dumps(dict(action=a.action,config=c,host_network_changes=False)));return
 if os.geteuid()!=0:p.error('root required for owned namespace access')
 STATE.mkdir(mode=0o700,exist_ok=True);protected(STATE)
 lock=STATE/'lock'
 if lock.is_symlink():raise ValueError('unsafe lock')
 fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as locked:
  fcntl.flock(locked,fcntl.LOCK_EX)
  marker=STATE/(name+'.json')
  if marker.is_symlink():raise ValueError('unsafe ownership marker')
  nsfile=Path('/run/netns')/ns
  site_path=Path('/var/lib/nextgen-sites')/ns
  protected(site_path);site_marker=site_path/'ownership.json'
  if site_marker.is_symlink():raise ValueError('unsafe site marker')
  site=json.loads(site_marker.read_text());inode=nsfile.stat().st_ino;boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
  if site['inode']!=inode or site.get('boot_id')!=boot:raise ValueError('unowned or stale site namespace')
  def ip(*args):return run(['ip','-n',ns,*args])
  links=json.loads(ip('-d','-j','link','show'));link=next((v for v in links if v['ifname']==name),None)
  owned=json.loads(marker.read_text()) if marker.exists() else None
  if owned and owned['config']!=c:raise ValueError('owned config differs; remove with the original config first')
  if link:
   if not owned or owned['inode']!=inode or owned['boot_id']!=boot or link.get('ifalias')!=owned['alias'] or link['ifindex']!=owned.get('ifindex'):raise ValueError('link ownership mismatch')
  if a.action=='status':print(json.dumps(dict(present=link is not None,owned=owned is not None,link=link)));return
  if a.action=='remove':
   if not owned:
    if link:raise ValueError('unmanaged link')
    print('absent');return
   if not link and owned['boot_id']==boot and owned['inode']!=inode:raise ValueError('namespace changed')
   if link:ip('link','delete',name)
   marker.unlink();print('removed owned overlay');return
  if link:
   info=link.get('linkinfo',{});data=info.get('info_data',{})
   assigned=json.loads(ip('-j','address','show','dev',name))[0].get('addr_info',[])
   address=ipaddress.IPv4Interface(c['address'])
   if link.get('mtu')!=c['mtu'] or info.get('info_kind')!=c['kind'] or data.get('local')!=c['local'] or data.get('remote')!=c['remote'] or not any(v.get('local')==str(address.ip) and v.get('prefixlen')==address.network.prefixlen for v in assigned):raise ValueError('owned link drift')
   if c['kind']=='vxlan' and (data.get('id')!=c['vni'] or data.get('port')!=c['port'] or data.get('learning') is not False):raise ValueError('owned VXLAN drift')
   print('unchanged');return
  if owned and owned['boot_id']==boot:raise ValueError('unfinished operation; inspect then remove original state')
  all_addresses=json.loads(ip('-j','address','show'))
  addresses=[ipaddress.ip_interface(v['local']+'/'+str(v['prefixlen'])) for x in all_addresses for v in x.get('addr_info',[]) if v['family']=='inet']
  if not any(v['local']==c['local'] for x in all_addresses if x['ifname']=='wg0' for v in x.get('addr_info',[]) if v['family']=='inet'):raise ValueError('local owned wg0 address missing')
  for v in addresses:
   if v.network.overlaps(ipaddress.IPv4Interface(c['address']).network):raise ValueError('overlay subnet already in use')
  for route in json.loads(ip('-j','route','show')):
   if 'dst' in route and route['dst']!='default' and ipaddress.ip_network(route['dst']).overlaps(ipaddress.IPv4Interface(c['address']).network):raise ValueError('overlay route conflicts')
  route=json.loads(ip('-j','route','get',c['remote']))[0]
  if route.get('dev')!='wg0' or route.get('gateway'):raise ValueError('remote must route through owned wg0')
  parent=next(v for v in links if v['ifname']=='wg0')
  if parent.get('linkinfo',{}).get('info_kind')!='wireguard' or c['mtu']>parent['mtu']-{'gre':24,'vxlan':50,'ipip':20}[c['kind']]:raise ValueError('underlay type or MTU budget invalid')
  alias='nextgen-overlay:'+secrets.token_hex(16);owned=dict(config=c,inode=inode,boot_id=boot,alias=alias)
  marker.write_text(json.dumps(owned));marker.chmod(0o600);created=False
  try:
   args=['link','add',name,'type',c['kind']]
   if c['kind']=='vxlan':args+=['id',str(c['vni'])]
   args+=['local',c['local'],'remote',c['remote'],'dev','wg0','ttl','64']
   if c['kind']=='vxlan':args+=['dstport',str(c['port']),'nolearning']
   ip(*args);created=True;ip('link','set',name,'alias',alias)
   owned['ifindex']=next(v['ifindex'] for v in json.loads(ip('-j','link','show',name)))
   marker.write_text(json.dumps(owned));marker.chmod(0o600)
   ip('link','set',name,'mtu',str(c['mtu']),'up');ip('address','add',c['address'],'dev',name)
  except BaseException:
   if created:ip('link','delete',name)
   marker.unlink();raise
  print('owned overlay ready inside TCP-backed site')
if __name__=='__main__':main()
