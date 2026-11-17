#!/usr/bin/env python3
"""Manage a separate owned GRE/VXLAN service after the permanent site service."""
import argparse,hashlib,json,os
from pathlib import Path
import subprocess
from overlay import validate,protected

STATE=Path('/var/lib/nextgen-overlay-installer')
def digest(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def call(args):return subprocess.check_output(args,text=True,timeout=60).strip()
def main():
 import fcntl
 p=argparse.ArgumentParser();p.add_argument('action',choices=['install','status','remove']);p.add_argument('--config',type=Path,required=True);p.add_argument('--source',type=Path,default=Path(__file__).with_name('overlay.py'));p.add_argument('--apply',action='store_true');a=p.parse_args()
 c=validate(json.loads(a.config.read_text()));name=c['name'];unit='nextgen-overlay-'+name+'.service'
 if a.action!='status' and not a.apply:print(json.dumps(dict(action=a.action,unit=unit,config=c,host_network_changes=False)));return
 if os.geteuid()!=0:raise ValueError('root required')
 STATE.mkdir(mode=0o700,exist_ok=True);protected(STATE)
 lock=STATE/'lock';fd=os.open(lock,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'w') as f:
  fcntl.flock(f,fcntl.LOCK_EX)
  marker=STATE/(name+'.json')
  if marker.is_symlink():raise ValueError('unsafe installer marker')
  cfg=Path('/etc/nextgen-overlays')/(name+'.json');code=Path('/usr/local/lib/nextgen-overlays')/name/'overlay.py';service=Path('/etc/systemd/system')/unit
  owned=json.loads(marker.read_text()) if marker.exists() else None
  if owned:
   if owned['config']!=c:raise ValueError('config mismatch; remove original service first')
   for filename,expected in owned['hashes'].items():
    path=Path(filename)
    if path.is_symlink() or digest(path)!=expected:raise ValueError('owned file changed: '+filename)
  if a.action=='status':print(json.dumps(dict(owned=owned is not None,active=call(['systemctl','show',unit,'-p','ActiveState','--value']),enabled=subprocess.run(['systemctl','is-enabled','--quiet',unit]).returncode==0)));return
  if a.action=='remove':
   if not owned:raise ValueError('unowned service')
   call(['systemctl','stop',unit]);call(['systemctl','disable',unit])
   for filename in owned['hashes']:Path(filename).unlink()
   code.parent.rmdir();marker.unlink();call(['systemctl','daemon-reload']);print('removed owned overlay service');return
  if owned:
   call(['systemctl','enable','--now',unit]);print('unchanged');return
  if call(['systemctl','show',unit,'-p','LoadState','--value'])!='not-found':raise ValueError('unmanaged unit')
  for target in (cfg,code,service):
   if target.exists() or target.is_symlink():raise ValueError('unmanaged destination: '+str(target))
  for directory in [cfg.parent,code.parent.parent,code.parent]:
   directory.mkdir(mode=0o700,exist_ok=True);protected(directory)
  text=f'''[Unit]
Description=Owned {c['kind']} overlay inside {c['namespace']}
Requires=nextgen-site.service
After=nextgen-site.service
PartOf=nextgen-site.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/python3 -B {code} create --config {cfg} --apply
ExecStop=/usr/bin/python3 -B {code} remove --config {cfg} --apply
TimeoutStartSec=60
TimeoutStopSec=60
NoNewPrivileges=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/nextgen-overlays
PrivateTmp=yes
UMask=0077

[Install]
WantedBy=multi-user.target
'''
  runtime=Path('/var/lib/nextgen-overlays');runtime.mkdir(mode=0o700,exist_ok=True);protected(runtime)
  created=[]
  try:
   for target,data,mode in [(cfg,(json.dumps(c,indent=2)+'\n').encode(),0o600),(code,a.source.read_bytes(),0o644),(service,text.encode(),0o644)]:
    fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as out:out.write(data)
    created.append(target)
   marker.write_text(json.dumps(dict(config=c,unit=unit,hashes={str(q):digest(q) for q in created})));marker.chmod(0o600)
   call(['systemctl','daemon-reload']);call(['systemctl','enable','--now',unit])
  except BaseException:
   # Keep owned files and marker if stopping cannot be verified; never orphan a live service.
   call(['systemctl','stop',unit]);subprocess.run(['systemctl','disable',unit],capture_output=True)
   for q in created:q.unlink()
   marker.unlink(missing_ok=True);call(['systemctl','daemon-reload']);raise
  print('installed independent owned overlay service')
if __name__=='__main__':main()
