"""Summarize protected low-rate field evidence without exporting network identities."""
import hashlib,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
def summarize(r):
 flows={}
 for path,body in r['paths'].items():
  flows[path]={}
  for name,s in body['flows'].items():
   flows[path][name]={k:s[k] for k in ['sent','received','timeouts','connect_errors','corrupted','late','max_burst','rtt_max_ms']}
   flows[path][name]['deadline_miss_percent']=100*s['timeouts']/max(1,s['sent'])
 samples=r['samples'];windows=[];engine_windows=[]
 for a,b in zip(samples,samples[1:]):
  ca=a['resources']['cpu'];cb=b['resources']['cpu']
  if ca and cb:
   delta=[int(y)-int(x) for x,y in zip(ca.split()[1:9],cb.split()[1:9])];total=sum(delta)
   if total>0:windows.append(dict(seconds=b['timestamp']-a['timestamp'],total=total,steal=delta[7],busy=total-delta[3]-delta[4]-delta[7]))
  ua=a['resources'].get('engine_usage');ub=b['resources'].get('engine_usage');dt=b['timestamp']-a['timestamp']
  if ua and ub and dt>0 and ua['processes'].keys()==ub['processes'].keys() and all(ua['processes'][p]['start_ticks']==ub['processes'][p]['start_ticks'] for p in ua['processes']):
   ticks=sum(ub['processes'][p]['utime']+ub['processes'][p]['stime']-ua['processes'][p]['utime']-ua['processes'][p]['stime'] for p in ua['processes'])
   engine_windows.append(dict(seconds=dt,one_core_percent=100*ticks/ub['clock_ticks']/dt,cpu_count=ub['cpu_count']))
 total=sum(w['total'] for w in windows);secs=sum(w['seconds'] for w in engine_windows)
 resource=dict(host_busy_average_percent=100*sum(w['busy'] for w in windows)/total,steal_average_percent=100*sum(w['steal'] for w in windows)/total,steal_peak_window_percent=max(100*w['steal']/w['total'] for w in windows),engine_average_percent_of_one_core=sum(w['one_core_percent']*w['seconds'] for w in engine_windows)/secs,engine_peak_window_percent_of_one_core=max(w['one_core_percent'] for w in engine_windows),visible_cpus=engine_windows[0]['cpu_count'])
 identities={s.get('engine') for s in samples};stable=len(identities)==1 and None not in identities
 def accepted(path):
  expected={'ipv4_tcp','ipv4_udp'} | ({'ipv6_tcp','ipv6_udp'} if path=='site' else set())
  return r['complete'] and r['elapsed_seconds']>=600 and r['paths'][path]['complete'] and set(flows[path])==expected and all(s['sent']>=.9*600/(r['tcp_interval_seconds'] if n.endswith('tcp') else r['udp_interval_seconds']) and s['corrupted']==0 and s['connect_errors']==0 and ((s['timeouts']==0) if n.endswith('tcp') else (s['deadline_miss_percent']<=.5 and s['max_burst']<=3)) for n,s in flows[path].items())
 return dict(complete=r['complete'],elapsed_seconds=r['elapsed_seconds'],driver_sha256=r['driver_sha256'],measurement_revision=r['measurement_revision'],udp_deadline_ms=r['udp_deadline_ms'],udp_interval_seconds=r['udp_interval_seconds'],tcp_interval_seconds=r['tcp_interval_seconds'],flows=flows,resources=resource,stable_engine_identity=stable,sampling_errors=len(r['sampling_errors']),site_acceptance=accepted('site') and stable,direct_acceptance=accepted('direct'))
def main():
 result={'experiment':'600-second low-rate paired direct/site test','nodes':{},'production_certified':False,'github_published':False,'limitations':['Low-rate latency and stability test, not capacity or saturation benchmark','Ten minutes is shorter than one hour','CPU steal correlation does not establish exclusive causation','Probe payload rates exclude transport framing, acknowledgements and keepalives']}
 for node in ['iran','turkey']:
  p=ROOT/'.private/remote-lab'/f'{node}-low-load.json';r=json.loads(p.read_text());v=summarize(r);v['raw_sha256']=hashlib.sha256(p.read_bytes()).hexdigest();result['nodes'][node]=v
  q=ROOT/'docs/evidence'/f'{node}-low-load-cleanup.json';v['cleanup']=json.loads(q.read_text());v['cleanup_sha256']=hashlib.sha256(q.read_bytes()).hexdigest()
 result['complete']=all(v['complete'] for v in result['nodes'].values());result['site_acceptance']=all(v['site_acceptance'] for v in result['nodes'].values())
 (ROOT/'docs/evidence/low-load-two-carrier.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
 print(json.dumps(result,indent=2))
if __name__=='__main__':main()
