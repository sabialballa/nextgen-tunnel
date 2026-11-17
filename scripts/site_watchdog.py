#!/usr/bin/env python3
"""Bounded, client-side recovery of the owned site after peer/transport outages.

The listener is passive. Only the configured loopback initiating peer may be
rekeyed; no host routes, firewall or interface addresses are modified.
"""
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import time

STATE=Path('/var/lib/nextgen-stack-watchdog')

def run(args):return subprocess.run(args,capture_output=True,text=True,timeout=15)
def main():
    if os.geteuid()!=0:raise SystemExit('root required')
    config_bytes=Path('/etc/nextgen-stack/site.json').read_bytes();config_digest=hashlib.sha256(config_bytes).hexdigest();cfg=json.loads(config_bytes);name=cfg['name']
    if name!='ngt-site-main':raise ValueError('owned site required')
    if STATE.is_symlink():raise ValueError('symlink watchdog state')
    STATE.mkdir(mode=0o700,exist_ok=True)
    if STATE.stat().st_uid!=0 or STATE.stat().st_mode&0o022:raise ValueError('unsafe watchdog state')
    with (STATE/'lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        path=STATE/'state.json';boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip();now=time.monotonic()
        state=json.loads(path.read_text()) if path.exists() else {}
        if state.get('boot_id')!=boot or state.get('config_sha256')!=config_digest:state=dict(boot_id=boot,config_sha256=config_digest,failures=0,rekeys=0,engine_restarts=0,last_rekey=-100,last_restart=-100)
        if not cfg.get('endpoint'):state.update(mode='passive_listener',checked_at=time.time())
        else:
            endpoint=cfg['endpoint'].rsplit(':',1)
            if len(endpoint)!=2 or not ipaddress.IPv4Address(endpoint[0]).is_loopback:raise ValueError('loopback initiating carrier required')
            hosts=[ipaddress.ip_network(v,strict=True) for v in cfg['remote_routes']]
            peer=next((str(v.network_address) for v in hosts if v.prefixlen==v.max_prefixlen),None)
            if peer is None:raise ValueError('explicit peer host route required')
            # Test useful payloads as well as reachability. Two probes tolerate
            # an isolated lost packet without accepting a small-packet-only path.
            probe_start=time.monotonic();healthy=run(['ip','netns','exec',name,'ping','-n','-c','2','-i','0.2','-W','2','-s','1152',peer]).returncode==0
            streak=state.get('healthy_streak',0)+1 if healthy else 0
            if not healthy and not state['failures']:state['outage_start_monotonic']=probe_start
            if healthy and streak>=3:
                state['last_success_at']=time.time()
                if state['failures']:state['last_recovery_seconds']=time.monotonic()-state.get('outage_start_monotonic',probe_start);state['last_recovered_at']=time.time()
            state.update(mode='initiating_client',checked_at=time.time(),healthy=healthy,healthy_streak=streak,failures=0 if healthy and streak>=3 else state['failures']+(0 if healthy else 1))
            if not healthy and state['failures']>=3:
                config=Path('/var/lib/nextgen-sites')/name/'wg.conf'
                if config.is_symlink() or config.stat().st_uid!=0 or config.stat().st_mode&0o777!=0o600:raise ValueError('unsafe owned WireGuard config')
                restart=state['failures']>=6 and now-state['last_restart']>=60
                rekey=restart or now-state['last_rekey']>=30
                if restart:
                    run(['systemctl','restart','nextgen-engine.service']).check_returncode();state['engine_restarts']+=1;state['last_restart']=now
                if rekey:
                    run(['ip','netns','exec',name,'wg','set','wg0','peer',cfg['peer_public_key'],'remove']).check_returncode()
                    run(['ip','netns','exec',name,'wg','setconf','wg0',str(config)]).check_returncode();state['rekeys']+=1;state['last_rekey']=now
                    print('restored configured WireGuard peer after consecutive failed health checks',flush=True)
        tmp=path.with_suffix('.tmp')
        with tmp.open('w') as f:json.dump(state,f,indent=2);f.flush();os.fsync(f.fileno())
        tmp.chmod(0o600);tmp.replace(path)

if __name__=='__main__':main()
