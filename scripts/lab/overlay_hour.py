"""Paired GRE/VXLAN/IPIP plus base-site probes, bounded to one real hour."""
import argparse,hashlib,json,os,pathlib,queue,subprocess,sys,threading,time
from path_compare import kernel_engine_snapshot
D=pathlib.Path('/opt/nextgen-stack-stage/overlay-hour-v2');CODE=pathlib.Path('/usr/local/lib/nextgen-overlay-hour')
KINDS={'base':240,'gre':250,'vxlan':251,'ipip':252};PORT=21931
def call(args):return subprocess.check_output(args,text=True,timeout=20).strip()
def baseline():
 main=pathlib.Path('/var/lib/nextgen-stack-installer/ownership.json');files=json.loads(main.read_text())['hashes'].copy()
 for kind in ['gre','vxlan','ipip']:
  p=pathlib.Path('/var/lib/nextgen-overlay-installer')/('ngo-'+kind+'.json');files[str(p)]=hashlib.sha256(p.read_bytes()).hexdigest();files.update(json.loads(p.read_text())['hashes'])
 assert all(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()==v for p,v in files.items())
 return dict(files=files,main_marker_sha256=hashlib.sha256(main.read_bytes()).hexdigest(),routes=json.loads(call(['ip','-j','route','show'])),routes6=json.loads(call(['ip','-j','-6','route','show'])),firewall=call(['nft','list','ruleset']),forwarding=pathlib.Path('/proc/sys/net/ipv4/ip_forward').read_text())
def resources():
 r={}
 for name,path in [('cpu','/proc/stat'),('pressure_cpu','/proc/pressure/cpu'),('pressure_memory','/proc/pressure/memory'),('pressure_io','/proc/pressure/io')]:r[name]=pathlib.Path(path).read_text().splitlines()[0]
 result={}
 for pid in pathlib.Path('/sys/fs/cgroup/system.slice/nextgen-engine.service/cgroup.procs').read_text().split():
  try:
   proc=pathlib.Path('/proc')/pid;f=(proc/'stat').read_text().rsplit(') ',1)[1].split();result[pid]=dict(name=(proc/'exe').resolve().name,utime=int(f[11]),stime=int(f[12]),start_ticks=int(f[19]),rss_pages=int(f[21]))
  except FileNotFoundError:continue
 r['engine_usage']=dict(clock_ticks=os.sysconf('SC_CLK_TCK'),page_size=os.sysconf('SC_PAGE_SIZE'),cpu_count=os.cpu_count(),processes=result);return r
def save(name,r):
 p=D/(name+'.json');q=p.with_suffix('.tmp');q.write_text(json.dumps(r));q.chmod(0o600);q.replace(p)
def probe(node,seconds,name):
 assert not (D/(name+'.json')).exists()
 key=(D/'secret').read_bytes();other=2 if node=='iran' else 1;started=time.monotonic();messages=queue.Queue();children=[]
 r=dict(started_wall_time=time.time(),seconds_requested=seconds,elapsed_seconds=0,complete=False,paths={},samples=[],sampling_errors=[],measurement_revision=2,udp_deadline_ms=500,udp_interval_seconds=1,tcp_interval_seconds=2,driver_sha256=hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),worker_sha256=hashlib.sha256((CODE/'path_compare.py').read_bytes()).hexdigest(),boot_id=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip())
 def reader(kind,c):
  try:
   for line in c.stdout:messages.put((kind,json.loads(line)))
  except Exception as exc:messages.put(('reader_error',type(exc).__name__))
 for kind,subnet in KINDS.items():
  peer=f'10.77.240.{other}' if kind=='base' else f'10.78.{subnet}.{other}'
  cmd=['ip','netns','exec','ngt-site-main','runuser','-u','nobody','--','python3','-B',str(CODE/'path_compare.py'),'worker','--seconds',str(seconds),'--peer',peer,'--port',str(PORT),'--udp-interval','1','--tcp-interval','2']
  c=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);c.stdin.write(key.hex()+'\n');c.stdin.close();children.append(c);threading.Thread(target=reader,args=(kind,c),daemon=True).start()
 next_sample=0
 try:
  while not (set(r['paths'])==set(KINDS) and all(v['complete'] for v in r['paths'].values())):
   try:
    kind,value=messages.get(timeout=10)
    if kind=='reader_error':raise RuntimeError(value)
    r['paths'][kind]=value
   except queue.Empty:
    if any(c.poll() is not None for c in children):raise RuntimeError('worker stopped before final snapshot')
   r['elapsed_seconds']=time.monotonic()-started
   if r['elapsed_seconds']>=next_sample:
    sample=dict(timestamp=time.time())
    for label,fn in [('engine',lambda:kernel_engine_snapshot('nextgen-engine.service')),('resources',resources),('links',lambda:json.loads(call(['ip','-n','ngt-site-main','-d','-j','link','show'])))]:
     try:sample[label]=fn()
     except (OSError,ValueError,RuntimeError,subprocess.SubprocessError) as exc:r['sampling_errors'].append(dict(timestamp=time.time(),component=label,error=type(exc).__name__));sample[label]=None
    r['samples'].append(sample);next_sample=time.monotonic()-started+10
   save(name,r)
   if time.monotonic()-started>seconds+60:raise RuntimeError('probe completion bound exceeded')
  for c in children:
   c.wait(timeout=10)
   if c.returncode:raise RuntimeError('worker exited unsuccessfully')
  r['complete']=True;r['elapsed_seconds']=time.monotonic()-started
 finally:
  for c in children:
   if c.poll() is None:c.terminate();c.wait(timeout=10)
  r['finished_wall_time']=time.time();save(name,r)
 print(json.dumps(dict(complete=r['complete'],elapsed=r['elapsed_seconds'])))
def main():
 p=argparse.ArgumentParser();p.add_argument('action',choices=['prepare','echo','preflight','start','run','status','stop','reboot-check','cleanup']);p.add_argument('--node',choices=['iran','turkey'],required=True);p.add_argument('--seconds',type=int,default=3600);p.add_argument('--name',default='hour');a=p.parse_args();number=1 if a.node=='iran' else 2;other=3-number
 assert os.geteuid()==0 and D.is_dir() and not D.is_symlink()
 if a.action=='prepare':
  assert not (D/'before.json').exists();save('before',baseline());(D/'boot-before.txt').write_text(pathlib.Path('/proc/sys/kernel/random/boot_id').read_text());print('prepared');return
 if a.action=='echo':
  assert call(['systemctl','show','nextgen-overlay-hour-echo.service','-p','LoadState','--value'])=='not-found'
  cmd=['systemd-run','--quiet','--unit=nextgen-overlay-hour-echo','-p','RuntimeMaxSec=5400','-p','DynamicUser=yes','-p','MemoryMax=64M','-p','TasksMax=32','-p','NoNewPrivileges=yes','-p','ProtectSystem=strict','-p','ProtectHome=yes','-p','NetworkNamespacePath=/run/netns/ngt-site-main','-p','LoadCredential=secret:'+str(D/'secret'),'python3','-B',str(CODE/'path_compare.py'),'server','--secret','/run/credentials/nextgen-overlay-hour-echo.service/secret','--port',str(PORT)]
  for kind,subnet in KINDS.items():
   prefix='10.77.240' if kind=='base' else f'10.78.{subnet}';cmd+=['--bind',f'{prefix}.{number}','--allow',f'{prefix}.{other}']
  call(cmd);print('echo started');return
 if a.action in ['preflight','start']:
  if a.action=='preflight':name='preflight';seconds=5
  else:
   pre=json.loads((D/'preflight.json').read_text());assert pre['complete'] and all(s['received']>0 and s['timeouts']==0 and s['corrupted']==0 for v in pre['paths'].values() for s in v['flows'].values());name='hour';seconds=3600
  call(['systemd-run','--quiet','--unit=nextgen-overlay-'+name,'-p','RuntimeMaxSec='+str(seconds+120),'-p','MemoryMax=192M','-p','TasksMax=80','python3','-B',str(pathlib.Path(__file__).resolve()),'run','--node',a.node,'--seconds',str(seconds),'--name',name]);print(json.dumps(dict(started=name,seconds=seconds)));return
 if a.action=='run':
  assert a.name in ['hour','preflight','postboot-iran','postboot-turkey'] and a.seconds in [5,30,3600];probe(a.node,a.seconds,a.name);return
 if a.action=='status':
  r=json.loads((D/'hour.json').read_text());print(json.dumps(dict(complete=r['complete'],elapsed=round(r['elapsed_seconds']),errors={k:{n:dict(sent=s['sent'],timeouts=s['timeouts'],max_burst=s['max_burst']) for n,s in v['flows'].items()} for k,v in r['paths'].items()},sampling_errors=len(r['sampling_errors']))));return
 if a.action=='stop':
  for u in ['nextgen-overlay-hour-echo.service','nextgen-overlay-hour.service','nextgen-overlay-preflight.service']:
   if call(['systemctl','show',u,'-p','LoadState','--value'])!='not-found':call(['systemctl','stop',u])
  print('owned test units stopped');return
 if a.action=='reboot-check':
  before=(D/'boot-before.txt').read_text().strip();after=pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip();assert before!=after
  units=['nextgen-engine.service','nextgen-site.service','nextgen-site-watchdog.timer']+['nextgen-overlay-ngo-'+kind+'.service' for kind in ['gre','vxlan','ipip']]
  states={u:dict(active=subprocess.run(['systemctl','is-active','--quiet',u]).returncode==0,enabled=subprocess.run(['systemctl','is-enabled','--quiet',u]).returncode==0) for u in units}
  result=dict(before_boot_id=before,after_boot_id=after,fresh_boot_changed=True,units=states,owned_files_and_host_state_unchanged=baseline()==json.loads((D/'before.json').read_text()),observed_wall_time=time.time(),permanent_services_manually_started=False)
  result['success']=result['owned_files_and_host_state_unchanged'] and all(v['active'] and v['enabled'] for v in states.values());save('reboot-check',result);print(json.dumps(result));return
 if a.action=='cleanup':
  hour=json.loads((D/'hour.json').read_text());assert hour['complete'] and hour['elapsed_seconds']>=3600
  assert json.loads((D/'reboot-check.json').read_text())['success']
  for name in ['postboot-iran','postboot-turkey']:assert json.loads((D/(name+'.json')).read_text())['complete']
  assert baseline()==json.loads((D/'before.json').read_text())
  assert not call(['ss','-Hlnut',f'( sport = :{PORT} )'])
  (D/'secret').unlink()
  assert not CODE.is_symlink() and {q.name for q in CODE.iterdir()}=={'overlay_hour.py','path_compare.py'}
  for q in CODE.iterdir():assert not q.is_symlink() and q.is_file() and q.stat().st_uid==0;q.unlink()
  CODE.rmdir();result=dict(success=True,temporary_secret_removed=True,temporary_helpers_removed=True,main_and_overlay_files_unchanged=True,timestamp=time.time());save('cleanup',result);print(json.dumps(result))
if __name__=='__main__':main()
