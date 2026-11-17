"""Bounded low-rate experiment; never change the permanent stack."""
import argparse, hashlib, json, os, pathlib, subprocess, time, shutil, ipaddress
D=pathlib.Path('/opt/nextgen-stack-stage/low-load-m3')
CODE=pathlib.Path('/usr/local/lib/nextgen-low-load-test/path_compare.py')
MARKER=pathlib.Path('/var/lib/nextgen-stack-installer/ownership.json')
def call(args):return subprocess.check_output(args,text=True,timeout=30).strip()
def baseline():
 return dict(marker=hashlib.sha256(MARKER.read_bytes()).hexdigest(),files={p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in json.loads(MARKER.read_text())['hashes']},routes=call(['ip','-j','route','show']),firewall=call(['nft','list','ruleset']),forwarding=pathlib.Path('/proc/sys/net/ipv4/ip_forward').read_text())
def main():
 p=argparse.ArgumentParser();p.add_argument('action',choices=['setup','preflight','start','status','cleanup']);p.add_argument('--node',choices=['iran','turkey'],required=True);p.add_argument('--own-public',type=ipaddress.IPv4Address,required=True);p.add_argument('--peer-public',type=ipaddress.IPv4Address,required=True);a=p.parse_args()
 assert os.geteuid()==0 and not D.is_symlink()
 peer4='10.77.240.2' if a.node=='iran' else '10.77.240.1';peer6='fd77:240::2' if a.node=='iran' else 'fd77:240::1'
 public=str(a.peer_public);ownpublic=str(a.own_public)
 own4='10.77.240.1' if a.node=='iran' else '10.77.240.2';own6='fd77:240::1' if a.node=='iran' else 'fd77:240::2'
 units=['nextgen-low-direct','nextgen-low-site','nextgen-low-preflight','nextgen-low-probe']
 if a.action=='setup':
  if (D/'owner.json').exists():
   old=json.loads((D/'owner.json').read_text());assert old['kind']=='nextgen-low-load-m3' and baseline()==old['before']
   assert not (D/'probe.json').exists() and not CODE.parent.exists()
   for u in units:
    if call(['systemctl','show',u+'.service','-p','LoadState','--value'])!='not-found':
     call(['systemctl','stop',u+'.service'])
     subprocess.run(['systemctl','reset-failed',u+'.service'],capture_output=True)
  for u in units:assert call(['systemctl','show',u+'.service','-p','LoadState','--value'])=='not-found'
  assert (D/'secret').stat().st_mode&0o777==0o600
  if not (D/'owner.json').exists():(D/'owner.json').write_text(json.dumps(dict(kind='nextgen-low-load-m3',before=baseline(),created=time.time())))
  D.chmod(0o700);CODE.parent.mkdir(mode=0o755);shutil.copyfile(D/'path_compare.py',CODE);CODE.chmod(0o644)
  for kind,binds,allows in [('direct',[ownpublic],[public]),('site',[own4,own6],[peer4,peer6])]:
   cmd=['systemd-run','--quiet','--unit=nextgen-low-'+kind,'-p','RuntimeMaxSec=1000','-p','DynamicUser=yes','-p','MemoryMax=64M','-p','TasksMax=20','-p','NoNewPrivileges=yes','-p','ProtectSystem=strict','-p','ProtectHome=yes','-p','LoadCredential=secret:'+str(D/'secret')]
   if kind=='site':cmd+=['-p','NetworkNamespacePath=/run/netns/ngt-site-main']
   cmd+=['python3','-B',str(CODE),'server','--secret','/run/credentials/nextgen-low-'+kind+'.service/secret','--port','29401' if kind=='direct' else '21901']
   for v in binds:cmd+=['--bind',v]
   for v in allows:cmd+=['--allow',v]
   call(cmd)
  print(json.dumps({'setup':True}));return
 owner=json.loads((D/'owner.json').read_text());assert owner['kind']=='nextgen-low-load-m3'
 if a.action in ('start','preflight'):
  name='probe' if a.action=='start' else 'preflight';seconds=600 if name=='probe' else 5
  if name=='probe':
   ready=json.loads((D/'preflight.json').read_text());assert ready['complete']
   assert all(s['received']>0 and s['timeouts']==0 and s['corrupted']==0 for v in ready['paths'].values() for s in v['flows'].values())
  assert not (D/(name+'.json')).exists()
  call(['systemd-run','--quiet','--unit=nextgen-low-'+name,'-p','RuntimeMaxSec='+str(seconds+60),'-p','MemoryMax=128M','-p','TasksMax=40','python3','-B',str(CODE),'run','--secret',str(D/'secret'),'--seconds',str(seconds),'--peer',peer4,'--peer',peer6,'--direct-peer',public,'--udp-interval','1','--tcp-interval','2','--output',str(D/(name+'.json'))])
  print(json.dumps({'started':name,'seconds':seconds}));return
 if a.action=='status':
  q=D/'probe.json'
  if not q.exists():q=D/'preflight.json'
  r=json.loads(q.read_text());print(json.dumps({k:r[k] for k in ('complete','elapsed_seconds','paths','sampling_errors')}));return
 if a.action=='cleanup':
  r=json.loads((D/'probe.json').read_text());assert r['complete'] and r['elapsed_seconds']>=600
  for u in units:
   if call(['systemctl','show',u+'.service','-p','LoadState','--value'])!='not-found':call(['systemctl','stop',u+'.service'])
  assert baseline()==owner['before'],'permanent state changed'
  assert all(call(['systemctl','is-active',u])=='active' for u in ['nextgen-engine.service','nextgen-site.service'])
  assert not call(['ss','-Hlntup','( sport = :29401 or sport = :21901 )'])
  for name in ['secret','path_compare.py','low_load_fixture.py']:
   q=D/name;assert q.is_file() and not q.is_symlink() and q.stat().st_uid==0;q.unlink()
  assert not CODE.parent.is_symlink() and {p.name for p in CODE.parent.iterdir()}=={'path_compare.py'}
  CODE.unlink();CODE.parent.rmdir()
  result=dict(success=True,main_unchanged=True,temporary_credentials_removed=True,temporary_units_stopped=True,timestamp=time.time())
  (D/'cleanup.json').write_text(json.dumps(result));print(json.dumps(result))
if __name__=='__main__':main()
