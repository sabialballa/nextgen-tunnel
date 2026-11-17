"""Sanitized paired hour and real-reboot comparison; never certify production."""
import hashlib,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
KINDS=['base','gre','vxlan','ipip']
def usage(samples):
 windows=[];engine=[]
 for a,b in zip(samples,samples[1:]):
  ar=a.get('resources');br=b.get('resources');dt=b['timestamp']-a['timestamp']
  if not ar or not br or dt<=0:continue
  delta=[int(y)-int(x) for x,y in zip(ar['cpu'].split()[1:9],br['cpu'].split()[1:9])];total=sum(delta)
  if total>0:windows.append(dict(total=total,steal=delta[7],busy=total-delta[3]-delta[4]-delta[7],seconds=dt,start=a['timestamp'],end=b['timestamp']))
  ua=ar['engine_usage'];ub=br['engine_usage']
  if ua['processes'].keys()==ub['processes'].keys() and all(ua['processes'][p]['start_ticks']==ub['processes'][p]['start_ticks'] for p in ua['processes']):
   ticks=sum(ub['processes'][p]['utime']+ub['processes'][p]['stime']-ua['processes'][p]['utime']-ua['processes'][p]['stime'] for p in ua['processes']);engine.append((dt,100*ticks/ub['clock_ticks']/dt))
 total=sum(w['total'] for w in windows);seconds=sum(w[0] for w in engine)
 return dict(visible_cpus=next(s['resources']['engine_usage']['cpu_count'] for s in samples if s.get('resources')),host_busy_average_percent=100*sum(w['busy'] for w in windows)/total,steal_average_percent=100*sum(w['steal'] for w in windows)/total,steal_peak_window_percent=max(100*w['steal']/w['total'] for w in windows),engine_average_percent_of_one_core=sum(dt*v for dt,v in engine)/seconds,engine_peak_window_percent_of_one_core=max(v for dt,v in engine),max_sampling_gap_seconds=max(w['seconds'] for w in windows))
def summarize(r,required=3600):
 paths={};events={}
 for kind,v in r['paths'].items():
  flows={}
  for name,s in v['flows'].items():
   f={key:s[key] for key in ['sent','received','timeouts','connect_errors','corrupted','late','max_burst','rtt_max_ms']};f['mean_timely_rtt_ms']=s['rtt_sum_ms']/max(1,s['received']);f['deadline_miss_percent']=100*s['timeouts']/max(1,s['sent']);flows[name]=f
  paths[kind]=dict(complete=v['complete'],flows=flows)
  paths[kind]['strict_acceptance']=r['complete'] and r['elapsed_seconds']>=required and v['complete'] and set(flows)=={'ipv4_tcp','ipv4_udp'} and all(s['corrupted']==0 and s['connect_errors']==0 and s['sent']>=.9*required/(2 if name.endswith('tcp') else 1) and ((s['timeouts']==0) if name.endswith('tcp') else s['deadline_miss_percent']<=.5 and s['max_burst']<=3) for name,s in flows.items())
  events[kind]=[e['timestamp'] for e in v['flows']['ipv4_udp']['events']]
 identities={s.get('engine') for s in r['samples']};stable=len(identities)==1 and None not in identities
 linkidentities=set();links_present=True
 for s in r['samples']:
  links=s.get('links')
  if links is None:links_present=False;continue
  selected={v['ifname']:(v['ifindex'],v.get('ifalias'),v['mtu']) for v in links if v['ifname'] in ['wg0','ngo-gre','ngo-vxlan','ngo-ipip']}
  if set(selected)!=set(['wg0','ngo-gre','ngo-vxlan','ngo-ipip']):links_present=False
  linkidentities.add(json.dumps(selected,sort_keys=True))
 for p in paths.values():p['strict_acceptance']=p['strict_acceptance'] and stable and links_present and len(linkidentities)==1
 near={k:dict(udp_events=len(events[k]),events_with_base_event_within_one_second=sum(any(abs(t-b)<=1 for b in events['base']) for t in events[k])) for k in KINDS if k!='base'}
 return dict(complete=r['complete'],elapsed_seconds=r['elapsed_seconds'],started_wall_time=r['started_wall_time'],finished_wall_time=r.get('finished_wall_time'),measurement_revision=r['measurement_revision'],driver_sha256=r['driver_sha256'],worker_sha256=r['worker_sha256'],udp_deadline_ms=500,udp_interval_seconds=1,tcp_interval_seconds=2,paths=paths,stable_engine_identity=stable,stable_overlay_identities=links_present and len(linkidentities)==1,sampling_errors=len(r['sampling_errors']),resources=usage(r['samples']),udp_event_time_neighborhood=near)
def main():
 report=dict(nodes={},observed_ranking=[],production_certified=False,github_published=False,limitations=['One-hour concurrent low-rate trial on shared physical hosts and TCP carrier','No independent path diversity; overlay ranking cannot isolate causation','UDP statistics are500ms deadline misses, not proof of permanent loss','Time-neighborhood event matching does not match the same application packets','TCP timeout criterion differs from500ms UDP; latency can remain without TCP failures','UDP mean/max RTT describe timely successful responses and exclude deadline misses','Reboot recovery observation is an upper observation bound, not exact application downtime'])
 for node in ['iran','turkey']:
  p=ROOT/'.private/remote-lab'/f'{node}-overlay-hour.json';r=json.loads(p.read_text());s=summarize(r);assert s['complete'] and s['elapsed_seconds']>=3600;s['raw_sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
  for label in ['reboot-check','cleanup','postboot-turkey','postboot-iran','final']:
   suffix='hour-final' if label=='final' else label
   q=ROOT/'.private/remote-lab'/f'{node}-overlay-{suffix}.json';v=json.loads(q.read_text());s[label+'_raw_sha256']=hashlib.sha256(q.read_bytes()).hexdigest()
   if label.startswith('postboot'):
    s[label]=dict(complete=v['complete'],elapsed_seconds=v['elapsed_seconds'],paths={k:{name:{f:state[f] for f in ['sent','received','timeouts','corrupted','late','max_burst']} for name,state in body['flows'].items()} for k,body in v['paths'].items()})
    s[label]['connectivity_success']=v['complete'] and set(v['paths'])==set(KINDS) and all(state['received']>0 and state['corrupted']==0 for body in v['paths'].values() for state in body['flows'].values())
    s[label]['zero_deadline_errors']=all(state['timeouts']==0 for body in v['paths'].values() for state in body['flows'].values())
   else:s[label]=v
  assert s['reboot-check']['success'] and s['cleanup']['success'] and s['final']['success'];report['nodes'][node]=s
  q=ROOT/'.private/remote-lab'/f'{node}-overlay-reboot-observation.json';observation=json.loads(q.read_text());assert observation['reboot_verified'];s['reboot_observation']=dict(reboot_verified=True,observation_elapsed_seconds=observation['observation_elapsed_seconds'],permanent_services_manually_started=observation['permanent_services_manually_started']);s['reboot_observation_raw_sha256']=hashlib.sha256(q.read_bytes()).hexdigest()
 for kind in KINDS:
  f=[n['paths'][kind]['flows'] for n in report['nodes'].values()];miss=sum(v['ipv4_udp']['timeouts'] for v in f);sent=sum(v['ipv4_udp']['sent'] for v in f)
  report['observed_ranking'].append(dict(kind=kind,udp_sent=sent,udp_deadline_misses=miss,udp_deadline_miss_percent=100*miss/sent,max_udp_burst=max(v['ipv4_udp']['max_burst'] for v in f),tcp_errors=sum(v['ipv4_tcp']['timeouts'] for v in f),strict_acceptance_both_nodes=all(n['paths'][kind]['strict_acceptance'] for n in report['nodes'].values())))
 report['observed_ranking'].sort(key=lambda v:(v['udp_deadline_miss_percent'],v['max_udp_burst']))
 report['reboot_verified_both_nodes']=all(n['reboot-check']['fresh_boot_changed'] and not n['reboot-check']['permanent_services_manually_started'] for n in report['nodes'].values())
 report['postboot_connectivity_both_trials']=all(n[label]['connectivity_success'] for n in report['nodes'].values() for label in ['postboot-turkey','postboot-iran'])
 report['common_hour_overlap_seconds']=min(n['finished_wall_time'] for n in report['nodes'].values())-max(n['started_wall_time'] for n in report['nodes'].values())
 (ROOT/'docs/evidence/overlay-hour-comparison.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8');print(json.dumps(report['observed_ranking'],indent=2))
if __name__=='__main__':main()
