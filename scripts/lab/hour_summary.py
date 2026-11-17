#!/usr/bin/env python3
"""Publish bounded flow statistics without raw socket samples or peer addresses."""
import argparse
import hashlib
import json
import re
from pathlib import Path


def summarize(path):
    raw=path.read_bytes();r=json.loads(raw)
    out={k:r[k] for k in ('started_wall_time','finished_wall_time','elapsed_seconds','seconds_requested','complete','driver_sha256','measurement_revision','udp_deadline_ms') if k in r}
    out['raw_sha256']=hashlib.sha256(raw).hexdigest();out['paths']={}
    for name,data in r['paths'].items():
        flows={}
        for kind,v in data['flows'].items():
            flows[kind]={k:v[k] for k in ('sent','received','timeouts','reconnects','connect_errors','corrupted','late','max_burst','rtt_sum_ms','rtt_max_ms')}
            flows[kind]['deadline_loss_percent']=100*(v['sent']-v['received'])/v['sent'] if v['sent'] else None
        out['paths'][name]=dict(complete=data['complete'],flows=flows)
    engines=[s['engine'] for s in r.get('samples',[])]
    out['engine_stable']=bool(engines) and all(isinstance(e,str) for e in engines) and len(set(engines))==1 and all(('ActiveState=active' in e or 'KernelSnapshot=1\n' in e) and 'MainPID=0\n' not in e for e in engines)
    out['sampling_error_count']=len(r.get('sampling_errors',[]))
    f=out['paths']['site']['flows']
    out['site_acceptance']=out['complete'] and out['elapsed_seconds']>=out['seconds_requested'] and out['engine_stable'] and len(f)==4 and all(v['received']>0 and v['corrupted']==0 and v['connect_errors']==0 and (v['timeouts']==0 and v['reconnects']==0 if k.endswith('tcp') else v['deadline_loss_percent']<=.5 and v['max_burst']<=3) for k,v in f.items())
    return out


def main():
    p=argparse.ArgumentParser();p.add_argument('--private-directory',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--label',default='rc2');a=p.parse_args()
    if not re.fullmatch(r'rc[0-9]+',a.label):p.error('release candidate label required')
    nodes={n:summarize(a.private_directory/(n+'-hour-'+a.label+'.json')) for n in ('iran','turkey')}
    report=dict(version='0.3.0-'+a.label,nodes=nodes,hour_complete=all(r['complete'] and r['elapsed_seconds']>=3600 for r in nodes.values()),hour_site_acceptance=all(r['site_acceptance'] and r['seconds_requested']==3600 for r in nodes.values()),production_certified=False)
    boots={};post={}
    for n in nodes:
        path=a.output.parent/(n+'-'+a.label+'-reboot.json')
        if path.exists():
            raw=path.read_bytes();r=json.loads(raw)
            boots[n]={k:r[k] for k in ('success','fresh_boot_changed','observation_elapsed_seconds','permanent_services_manually_started','before_boot_id','after_boot_id')}
            boots[n]['evidence_sha256']=hashlib.sha256(raw).hexdigest()
        path=a.private_directory/(n+'-postboot-'+a.label+'.json')
        if path.exists():post[n]=summarize(path)
    report['reboots']=boots;report['postboot']=post
    report['reboot_tested']=len(boots)==2
    report['both_reboots_recovered']=all(r['success'] and r['fresh_boot_changed'] and not r['permanent_services_manually_started'] for r in boots.values()) if len(boots)==2 else None
    report['postboot_site_acceptance']=all(r['seconds_requested']==120 and r['site_acceptance'] for r in post.values()) if len(post)==2 else None
    a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ('nodes','reboots','postboot')}))


if __name__=='__main__':main()
