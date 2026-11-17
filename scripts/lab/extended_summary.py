#!/usr/bin/env python3
"""Sanitize the completed two-carrier hour and paired TCP alternative trial."""
import argparse
import hashlib
import json
from pathlib import Path
from hour_summary import summarize


def resources(raw):
    samples=raw.get('samples',[]);windows=[];invalid=0
    udp=[e['timestamp'] for k,v in raw['paths']['site']['flows'].items() if k.endswith('udp') for e in v['events']]
    for a,b in zip(samples,samples[1:]):
        x=a.get('resources',{}).get('cpu');y=b.get('resources',{}).get('cpu')
        if not x or not y:invalid+=1;continue
        delta=[int(v)-int(u) for u,v in zip(x.split()[1:9],y.split()[1:9])];total=sum(delta)
        if len(delta)!=8 or total<=0 or any(v<0 for v in delta):invalid+=1;continue
        windows.append(dict(start=a['timestamp'],end=b['timestamp'],total_ticks=total,steal_ticks=delta[7],steal_percent=100*delta[7]/total,udp_error_events_near=sum(a['timestamp']-1<=t<=b['timestamp']+1 for t in udp)))
    return dict(max_cpu_steal_percent=max((w['steal_percent'] for w in windows),default=None),weighted_cpu_steal_percent=100*sum(w['steal_ticks'] for w in windows)/sum(w['total_ticks'] for w in windows) if windows else None,max_sampling_gap_seconds=max((b['timestamp']-a['timestamp'] for a,b in zip(samples,samples[1:])),default=None),invalid_resource_intervals=invalid,peak_windows=sorted(windows,key=lambda w:w['steal_percent'],reverse=True)[:5],definition_source='https://man7.org/linux/man-pages/man5/proc_stat.5.html',interpretation='Guest-reported CPU steal accounting; timing correlation is not exclusive proof of every outage cause')


def annotate(path):
    r=summarize(path);raw=json.loads(path.read_bytes());r['resources']=resources(raw)
    tcp=[e for k,v in raw['paths']['site']['flows'].items() if k.endswith('tcp') for e in v['events']]
    r['tcp_startup_connection_refusals']=sum(e['kind']=='ConnectionRefusedError' and e['timestamp']<=raw['started_wall_time']+5 for e in tcp)
    r['tcp_error_events_after_initial_5_seconds']=sum(e['timestamp']>raw['started_wall_time']+5 for e in tcp)
    return r


def main():
    p=argparse.ArgumentParser();p.add_argument('--private-directory',type=Path,required=True);p.add_argument('--output-directory',type=Path,required=True);a=p.parse_args()
    hour={n:annotate(a.private_directory/(n+'-two-hour-rc3.json')) for n in ('iran','turkey')}
    report=dict(version='0.3.0-rc3',carriers=2,measurement_revision=2,udp_deadline_ms=500,nodes=hour,hour_complete=all(r['complete'] and r['seconds_requested']==3600 and r['elapsed_seconds']>=3600 for r in hour.values()),hour_site_acceptance=all(r['site_acceptance'] for r in hour.values()),current_profile_hour_tested=True,production_certified=False,initial_aborted_attempt_counted=False,measurement_changes=['Ancillary monitor failures do not kill traffic workers','Process identity read from kernel cgroups/PID start ticks','Absolute application UDP deadline includes scheduling delay'],startup_note='Four Iran TCP connection refusals occurred in the initial echo-server startup window; retained in full-run counters and separated from later errors')
    (a.output_directory/'two-carrier-hour-rc3.json').write_text(json.dumps(report,indent=2)+'\n')
    paired={};starts=[];ends=[]
    for n in ('iran','turkey'):
        paired[n]={}
        raws={}
        for kind,suffix in (('main','paired-main'),('alternative','tcp-alternative')):
            path=a.private_directory/(n+'-'+suffix+'.json');r=annotate(path);paired[n][kind]=r;raws[kind]=json.loads(path.read_bytes());starts.append(r['started_wall_time']);ends.append(r['finished_wall_time'])
        events={k:[e['timestamp'] for name,v in raw['paths']['site']['flows'].items() if name.endswith('udp') for e in v['events']] for k,raw in raws.items()}
        paired[n]['udp_event_neighborhood']=dict(main_events=len(events['main']),alternative_events=len(events['alternative']),alternative_events_with_main_event_within_1s=sum(any(abs(t-u)<=1 for u in events['main']) for t in events['alternative']),interpretation='Time-neighborhood comparison, not matching the same application packet')
    result=dict(version='0.3.0-rc3',alternative='Trojan over TLS1.3 with mutual certificate verification, no smux',duration_requested_per_probe_seconds=300,common_overlap_seconds=max(0,min(ends)-max(starts)),nodes=paired,complete=all(r['complete'] and r['seconds_requested']==300 and r['elapsed_seconds']>=300 for n in paired.values() for k,r in n.items() if k in ('main','alternative')),main_short_acceptance=all(n['main']['site_acceptance'] for n in paired.values()),alternative_short_acceptance=all(n['alternative']['site_acceptance'] for n in paired.values()),alternative_promoted=False,production_certified=False,limitations=['Five minutes per probe is not one-hour validation','Concurrent trial adds both workloads to shared hosts and route','Port, SNI, TLS authentication and framing differ','CPU steal and shared path can affect both','Earlier reports used a less strict UDP receive-completion measurement'])
    for n in ('iran','turkey'):
        proof=a.output_directory/(n+'-two-alt-cleanup.json');r=json.loads(proof.read_bytes());assert r['success'];result.setdefault('cleanup_sha256',{})[n]=hashlib.sha256(proof.read_bytes()).hexdigest()
    result['alternative_removed_after_test']=True
    (a.output_directory/'tcp-alternative-comparison.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(hour_complete=report['hour_complete'],hour_acceptance=report['hour_site_acceptance'],paired_complete=result['complete'],main_short_acceptance=result['main_short_acceptance'],alternative_short_acceptance=result['alternative_short_acceptance'],common_overlap_seconds=result['common_overlap_seconds'])))


if __name__=='__main__':main()
