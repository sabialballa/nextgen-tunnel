#!/usr/bin/env python3
"""Publish selected acceptance metrics, never private configs or journal text."""
import argparse
import hashlib
import json
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--private-directory',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    profiles=('soak-early-failed','soak-smux-smoke','soak-hy-gecko-smoke','soak-fixed-mtu-smoke','soak-3h-final')
    snapshots=('hy-permanent-warm-pass','hy-final-reboot','hy-fixed-mtu-reboot','final-carrier-reboot','post-soak-final','post-cleanup-final')
    report=dict(scope='Two isolated WireGuard sites; outer connection initiated from Turkey. No physical LAN or host Internet routing.',selected_carrier='REALITY with smux',nodes={},production_acceptance=False)
    for node in ('iran','turkey'):
        data={}
        for name in profiles+snapshots:
            path=a.private_directory/(node+'-'+name+'.json')
            if not path.exists():continue
            raw=path.read_bytes();r=json.loads(raw)
            fields=('started_wall_time','finished_wall_time','duration_requested_seconds','elapsed_seconds','complete','success','scope','acceptance_criteria','flows','network_unchanged','boot_unchanged','binary_sha256','driver_sha256') if name in profiles else ('timestamp','boot_id','boot_id_changed','success','ownership_verified','private_material_root_only','host_routes_unchanged','host_firewall_unchanged','host_forwarding_unchanged','peer_endpoint_loopback','handshake_present','site_interfaces','units','binary_sha256','probe','test_helpers_removed')
            data[name]={k:r[k] for k in fields if k in r};data[name]['raw_sha256']=hashlib.sha256(raw).hexdigest()
            if 'error' in r:data[name]['failed_check_recorded_privately']=True
        path=a.private_directory/(node+'-watchdog-final.json')
        if path.exists():
            raw=path.read_bytes();r=json.loads(raw)
            data['watchdog_final']={k:r[k] for k in ('rekeys','engine_restarts','healthy','healthy_streak','last_recovery_seconds','last_recovered_at','mode','checked_at') if k in r};data['watchdog_final']['raw_sha256']=hashlib.sha256(raw).hexdigest()
        path=a.private_directory/(node+'-soak-passive-diagnostics.jsonl')
        if path.exists():
            raw=path.read_bytes();data['passive_diagnostics']=dict(raw_sha256=hashlib.sha256(raw).hexdigest(),samples=len(raw.splitlines()),contains_peer_addresses=True,private_evidence_only=True)
        report['nodes'][node]=data
    report['three_hour_completed']=all(report['nodes'][n].get('soak-3h-final',{}).get('complete') and report['nodes'][n]['soak-3h-final'].get('elapsed_seconds',0)>=10800 for n in report['nodes'])
    report['production_acceptance']=bool(report['three_hour_completed'] and all(report['nodes'][n]['soak-3h-final'].get('success') and report['nodes'][n].get('final-carrier-reboot',{}).get('success') and report['nodes'][n].get('post-cleanup-final',{}).get('success') for n in report['nodes']))
    a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(dict(output=str(a.output),production_acceptance=report['production_acceptance'],three_hour_completed=bool(report['three_hour_completed']))))

if __name__=='__main__':main()
