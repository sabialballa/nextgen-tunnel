#!/usr/bin/env python3
"""Evidence for an owned permanent stack; never export config or private keys."""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess
import time

def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--peer4',required=True);p.add_argument('--peer6',required=True);p.add_argument('--expect-reboot',action='store_true');p.add_argument('--after-cleanup',action='store_true');a=p.parse_args()
    def cmd(args):return subprocess.check_output(args,text=True,timeout=60).strip()
    boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();r=dict(timestamp=time.time(),boot_id=boot,units={})
    try:
        for unit in ('nextgen-site.service','nextgen-engine.service','nextgen-site-watchdog.timer')+(() if a.after_cleanup else ('nextgen-acceptance-echo.service',)):
            data=dict(line.split('=',1) for line in cmd(['systemctl','show',unit,'-p','ActiveState','-p','SubState','-p','MainPID','-p','NRestarts','-p','User','-p','DynamicUser']).splitlines() if '=' in line)
            data['enabled']=subprocess.run(['systemctl','is-enabled','--quiet',unit]).returncode==0;r['units'][unit]=data
        marker=json.loads(Path('/var/lib/nextgen-stack-installer/ownership.json').read_text());r['ownership_verified']=all(hashlib.sha256(Path(path).read_bytes()).hexdigest()==expected for path,expected in marker['hashes'].items())
        r['binary_sha256']={name:hashlib.sha256((Path('/usr/local/lib/nextgen-stack')/name).read_bytes()).hexdigest() for name in ('nextgen-tunnel','sing-box')}
        r['private_material_root_only']=all(Path(path).stat().st_uid==0 and Path(path).stat().st_mode&0o777==0o600 for path in marker['hashes'] if path.startswith('/etc/nextgen-stack/'))
        before=json.loads((a.directory/'routes-before.json').read_text());after=json.loads(cmd(['ip','-j','route','show']));r['host_routes_unchanged']=sorted(before,key=lambda v:json.dumps(v,sort_keys=True))==sorted(after,key=lambda v:json.dumps(v,sort_keys=True))
        r['host_firewall_unchanged']=(a.directory/'firewall-before.txt').read_text().strip()==cmd(['nft','list','ruleset']);r['host_forwarding_unchanged']=(a.directory/'forwarding-before.txt').read_text().strip()==Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()
        r['site_interfaces']=[v['ifname'] for v in json.loads(cmd(['ip','-n','ngt-site-main','-j','link','show']))]
        endpoints=cmd(['ip','netns','exec','ngt-site-main','wg','show','wg0','endpoints']).splitlines();r['peer_endpoint_loopback']=all(line.split()[1]!='(none)' and ipaddress.ip_address(line.split()[1].rsplit(':',1)[0].strip('[]')).is_loopback for line in endpoints) and len(endpoints)==1
        latest=[int(line.split()[-1]) for line in cmd(['ip','netns','exec','ngt-site-main','wg','show','wg0','latest-handshakes']).splitlines()];r['handshake_present']=bool(latest) and min(latest)>0
        if a.after_cleanup:
            checks=[]
            for family,peer in (('ipv4',a.peer4),('ipv6',a.peer6)):
                result=subprocess.run(['ip','netns','exec','ngt-site-main','ping','-n','-c','3','-W','2','-s','1152',peer],capture_output=True,text=True,timeout=12)
                checks.append(dict(family=family,protocol='icmp',payload_bytes=1152,success=result.returncode==0))
            probe=dict(checks=checks,success=all(v['success'] for v in checks))
            r['test_helpers_removed']=not Path('/etc/systemd/system/nextgen-acceptance-echo.service').exists() and not Path('/usr/local/lib/nextgen-stack-test').exists() and subprocess.run(['systemctl','is-active','--quiet','nextgen-acceptance-soak-final.service']).returncode!=0
        else:
            probe_result=subprocess.run(['ip','netns','exec','ngt-site-main','python3','/usr/local/lib/nextgen-stack-test/site_probe.py','probe','--peer',a.peer4,'--peer',a.peer6],capture_output=True,text=True,timeout=60)
            probe=json.loads(probe_result.stdout)
            for check in probe['checks']:check['family']='ipv6' if ':' in check.pop('peer') else 'ipv4'
        r['probe']=probe
        r['boot_id_changed']=boot!=(a.directory/'boot-before.txt').read_text().strip()
        r['success']=all(v['ActiveState']=='active' and v['enabled'] for v in r['units'].values()) and all(r[k] for k in ('ownership_verified','private_material_root_only','host_routes_unchanged','host_firewall_unchanged','host_forwarding_unchanged','peer_endpoint_loopback','handshake_present')) and r['probe']['success'] and set(r['site_interfaces'])=={'lo','wg0'} and (not a.expect_reboot or r['boot_id_changed']) and (not a.after_cleanup or r['test_helpers_removed'])
    except Exception as exc:r.update(success=False,error=str(exc))
    a.output.write_text(json.dumps(r,indent=2));a.output.chmod(0o600);print(json.dumps(dict(success=r['success'],boot_id=boot,output=str(a.output))));raise SystemExit(0 if r['success'] else 1)

if __name__=='__main__':main()
