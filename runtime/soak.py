import subprocess,pathlib,json,time,re,statistics,signal,os
import argparse
a=argparse.ArgumentParser();a.add_argument('--directory',required=True);a.add_argument('--peer',required=True);a.add_argument('--tcp-port',type=int,required=True);a.add_argument('--udp-port',type=int,required=True);a.add_argument('--role',required=True);a.add_argument('--seconds',type=int,default=900);a.add_argument('--tcp-mbit',type=int,default=20);a.add_argument('--udp-mbit',type=int,default=1);args=a.parse_args()
b=pathlib.Path(args.directory);peer=args.peer;tcpport=args.tcp_port;udpport=args.udp_port;role=args.role;duration=args.seconds
routes=json.loads(subprocess.check_output(['ip','-j','route','show','default'],text=True))
wan=next((r['dev'] for r in routes if r.get('dev')),None)
if not wan:raise RuntimeError('no default-route interface found')
nic_drop_path=pathlib.Path('/sys/class/net')/wan/'statistics/rx_dropped'

def svc():
 d={}
 for l in subprocess.check_output(['systemctl','show','gaming-raw','-p','MainPID','-p','NRestarts','-p','ActiveState'],text=True).splitlines():
  k,v=l.split('=',1);d[k]=v
 return d


def packet_counters(pid):
 out=subprocess.check_output(['ss','-0amp'],text=True);result={'drops':None,'buffer':None,'nic_rx_dropped':int(nic_drop_path.read_text())}
 for line in out.splitlines():
  if 'pid='+str(pid)+',' in line:
   d=re.search(r',d([0-9]+)[)]',line);v=re.search(r'rb([0-9]+)',line)
   if d:result['drops']=int(d.group(1))
   if v:result['buffer']=int(v.group(1))
 return result

def cpu():
 a=list(map(int,pathlib.Path('/proc/stat').read_text().splitlines()[0].split()[1:]));return sum(a[:8]),a[3]+a[4]

def pings(txt):
 vals=[]
 for l in txt.splitlines():
  t=re.search(r'\[([0-9.]+)\]',l);q=re.search(r'icmp_seq=([0-9]+)',l);r=re.search(r'time=([0-9.]+)',l)
  if t and q and r:vals.append((int(q.group(1)),float(t.group(1)),float(r.group(1))))
 return vals

initial=svc();capture_initial=packet_counters(initial['MainPID']);baseline=subprocess.run(['ping','-n','-c','20','-i','0.2','-W','1',peer],capture_output=True,text=True,timeout=12);(b/'baseline-ping.txt').write_text(baseline.stdout)
bv=[float(x) for x in re.findall(r'time=([0-9.]+)',baseline.stdout)]
if ' 0% packet loss' not in baseline.stdout or not bv or max(bv)>200:raise RuntimeError('baseline not healthy; no load started')
base=statistics.mean(bv);start=time.time();mono=time.monotonic();files=[];children=[];reason=None;highcpu=0;maxcpu=0;lastsave=0
pf=open(b/'ping.txt','w');files.append(pf);ping=subprocess.Popen(['stdbuf','-oL','ping','-D','-n','-i','1','-W','2',peer],stdout=pf);children.append(ping)
for proto,port,rate in [('tcp',tcpport,str(args.tcp_mbit)+'M'),('udp',udpport,str(args.udp_mbit)+'M')]:
 f=open(b/(proto+'-client.json'),'w');files.append(f);err=open(b/(proto+'-client.stderr'),'w');files.append(err)
 cmd=['iperf3','-c',peer,'-p',str(port),'-b',rate,'-t',str(duration),'-J']+(['-M','1120'] if proto=='tcp' else ['-u','-l','160'])
 children.append(subprocess.Popen(cmd,stdout=f,stderr=err))
s0=cpu();samples=[]
try:
 while True:
  time.sleep(2);elapsed=time.monotonic()-mono;now=time.time();vals=pings((b/'ping.txt').read_text());recent=vals[-30:];rtts=[x[2] for x in recent];state=svc();capture_now=packet_counters(state['MainPID']);s1=cpu();dt=s1[0]-s0[0];use=100*(1-(s1[1]-s0[1])/dt) if dt else 0;s0=s1;maxcpu=max(maxcpu,use);highcpu=highcpu+1 if use>75 else 0
  p95=sorted(rtts)[min(len(rtts)-1,int(len(rtts)*.95))] if rtts else None
  if state!=initial:reason='carrier PID/restart/state changed'
  if elapsed>10 and (not vals or now-vals[-1][1]>3.5):reason='no ping response for3.5seconds'
  if len(recent)>=20 and (p95>base+30 or max(rtts)>300):reason='rolling RTT quality threshold'
  if len(recent)>=20 and recent[-1][0]-recent[0][0]+1-len(set(v[0] for v in recent))>=2:reason='multiple ping sequence gaps in rolling window'
  if highcpu>=3:reason='host CPU above75% for three samples'
  if elapsed<duration-20 and any(p.poll() is not None for p in children[1:]):reason='benchmark client exited early'
  up=b/'udp-receiver.log';loss=[]
  if up.exists():
   for l in up.read_text(errors='replace').splitlines():
    m=re.search(r'([0-9]+)/([0-9]+) \(([0-9.]+)%\)',l)
    if m:loss.append((int(m.group(1)),int(m.group(2))))
  recentloss=loss[-10:];ld=sum(x[0] for x in recentloss);lt=sum(x[1] for x in recentloss);lp=100*ld/lt if lt else 0
  if elapsed>20 and lt>1000 and lp>.5:reason='rolling received UDP loss above0.5%'
  snap={'role':role,'elapsed_s':round(elapsed,1),'target_s':duration,'baseline_rtt_ms':base,'ping_responses':len(vals),'ping_sequence_gaps':vals[-1][0]-vals[0][0]+1-len(set(v[0] for v in vals)) if vals else None,'rolling_rtt_avg_ms':statistics.mean(rtts) if rtts else None,'rolling_rtt_p95_ms':p95,'rolling_rtt_max_ms':max(rtts) if rtts else None,'rolling_udp_loss_pct':lp,'host_cpu_pct':round(use,2),'host_cpu_max_pct':round(maxcpu,2),'carrier':state,'capture_receive_buffer':capture_now['buffer'],'capture_drop_start':capture_initial['drops'],'capture_drop_total':capture_now['drops'],'capture_drop_delta':capture_now['drops']-capture_initial['drops'] if capture_now['drops'] is not None and capture_initial['drops'] is not None else None,'nic_rx_drop_delta':capture_now['nic_rx_dropped']-capture_initial['nic_rx_dropped'],'stop_reason':reason}
  (b/'status.json').write_text(json.dumps(snap))
  if elapsed-lastsave>=15:
   with open(b/'monitor.jsonl','a') as f:f.write(json.dumps(snap)+'\n')
   lastsave=elapsed
  if reason:break
  if elapsed>=duration and all(p.poll() is not None for p in children[1:]):break
  if elapsed>duration+20:break
finally:
 for p in children:
  if p.poll() is None:p.send_signal(signal.SIGINT)
 for p in children:
  try:p.wait(timeout=5)
  except subprocess.TimeoutExpired:p.kill();p.wait()
 for f in files:f.close()
 vals=pings((b/'ping.txt').read_text());r=[v[2] for v in vals];snap.update({'elapsed_s':round(time.monotonic()-mono,1),'data_duration_completed':time.monotonic()-mono>=duration,'ping_responses':len(vals),'ping_sequence_gaps':max(v[0] for v in vals)-min(v[0] for v in vals)+1-len(set(v[0] for v in vals)) if vals else None,'all_rtt_avg_ms':statistics.mean(r) if r else None,'all_rtt_p95_ms':sorted(r)[int(len(r)*.95)] if r else None,'all_rtt_max_ms':max(r) if r else None,'stop_reason':reason,'finished':True});(b/'status.json').write_text(json.dumps(snap));(b/'summary.json').write_text(json.dumps(snap));print(json.dumps(snap),flush=True)
