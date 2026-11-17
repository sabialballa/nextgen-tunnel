#!/usr/bin/env python3
"""Offline transactional systemd installation of an engine and isolated WG site.

No host route, firewall, forwarding sysctl or SSH settings are changed.
Separate from the native core service. Secrets are never printed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time

from host_install import atomic, safe_path, preflight

ROOT=Path(__file__).resolve().parents[1]
LIB=Path('/usr/local/lib/nextgen-stack')
ETC=Path('/etc/nextgen-stack')
STATE=Path('/var/lib/nextgen-stack-installer')
MARKER=STATE/'ownership.json'
JOURNAL=STATE/'transaction.json'
UNITS=('nextgen-site.service','nextgen-engine.service','nextgen-site-watchdog.timer','nextgen-site-watchdog.service')
FILES=tuple(str(p) for p in [LIB/'nextgen-tunnel',LIB/'sing-box',LIB/'site.py',ETC/'engine.json',ETC/'site.json',ETC/'wg.key',ETC/'wg.psk',*[ETC/f'tls-{i}.pem' for i in range(4)],*[Path('/etc/systemd/system')/u for u in UNITS],LIB/'site_watchdog.py'])
LEGACY_FILES=set(FILES)-{str(LIB/'site_watchdog.py'),'/etc/systemd/system/nextgen-site-watchdog.timer','/etc/systemd/system/nextgen-site-watchdog.service'}
PRE_REDUNDANCY_FILES=set(FILES)
FILES=FILES+(str(ETC/'redundancy.json'),)

def run(args,check=True):return subprocess.run([str(v) for v in args],capture_output=True,text=True,check=check,timeout=60)
def digest(data):return hashlib.sha256(data).hexdigest()
def hashes(files):return {k:digest(v) for k,v in files.items()}
def load(path):
    data=safe_path(path).read_bytes()
    if len(data)>1<<20:raise ValueError('config exceeds 1 MiB')
    return json.loads(data)
def secure_directory(path,mode=0o700):
    if any(p.is_symlink() for p in (path,*path.parents)):raise ValueError('symlink directory')
    path.mkdir(parents=True,exist_ok=True,mode=mode)
    st=path.stat()
    if st.st_uid!=0 or st.st_mode&0o022:raise ValueError('unsafe managed directory')

def binary(path,expected):
    data=safe_path(path).read_bytes()
    if digest(data)!=expected.lower():raise ValueError('binary SHA256 mismatch')
    arch={'x86_64':62,'aarch64':183}.get(platform.machine())
    if len(data)<20 or data[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(data[18:20],'little')!=arch:raise ValueError('matching Linux ELF64 required')
    return data

def content(a):
    result={FILES[0]:binary(a.binary,a.sha256),FILES[1]:binary(a.engine,a.engine_sha256),FILES[2]:(ROOT/'scripts/site.py').read_bytes(),str(LIB/'site_watchdog.py'):(ROOT/'scripts/site_watchdog.py').read_bytes()}
    cfg=load(a.engine_config);site=load(a.site_config)
    redundancy=dict(enabled=False)
    if 'redundant_listener_port' in site:
        port=site['redundant_listener_port']
        if site.get('endpoint') or type(port)!=int or not 1024<=port<=65535 or port==site['listen_port']:raise ValueError('distinct passive loopback relay port required')
        rules=cfg.get('route',{}).get('rules',[])
        if not any(r.get('ip_cidr')==['127.0.0.1/32'] and r.get('port')==[port] and r.get('action')=='route' for r in rules):raise ValueError('listener engine must route exclusively to configured relay port')
        redundancy=dict(enabled=True,mode='listener',listen=f'127.0.0.1:{port}',target=f"127.0.0.1:{site['listen_port']}")
    carriers=[v for v in cfg.get('inbounds',[]) if v.get('type')=='direct' and v.get('network')=='udp']
    if site.get('endpoint') and len(carriers)>=2 and all(site['endpoint']!=f"{v.get('listen')}:{v.get('listen_port')}" for v in carriers):
        if len(carriers)>4 or any(v.get('listen')!='127.0.0.1' for v in carriers):raise ValueError('bounded loopback carriers required')
        backends=[f"127.0.0.1:{v['listen_port']}" for v in carriers]
        routes={tag:r.get('outbound') for r in cfg.get('route',{}).get('rules',[]) for tag in r.get('inbound',[])}
        if len({routes.get(v.get('tag')) for v in carriers})!=len(carriers) or any(not routes.get(v.get('tag')) for v in carriers):raise ValueError('independent explicit carrier outbound routes required')
        redundancy=dict(enabled=True,listen=site['endpoint'],target=f"127.0.0.1:{site['listen_port']}",backends=backends)
        # Keep the listener's authenticated WireGuard endpoint on a live carrier
        # even when application traffic is predominantly listener-to-initiator.
        site['persistent_keepalive']=1
    result[str(ETC/'redundancy.json')]=json.dumps(redundancy).encode()
    if site.get('name')!='ngt-site-main':raise ValueError('managed stack requires site name ngt-site-main')
    if not cfg.get('inbounds') or any(v.get('type') not in ('direct','vless','hysteria2') for v in cfg['inbounds']):raise ValueError('stack supports explicit loopback carriers or authenticated listener inbounds only')
    for inbound in cfg['inbounds']:
        if inbound['type']=='direct' and inbound.get('listen')!='127.0.0.1':raise ValueError('carrier must be loopback-only')
    result[str(ETC/'wg.key')]=safe_path(site['private_key_file']).read_bytes()
    site['private_key_file']=str(ETC/'wg.key')
    result[str(ETC/'wg.psk')]=b''
    if site.get('preshared_key_file'):
        result[str(ETC/'wg.psk')]=safe_path(site['preshared_key_file']).read_bytes();site['preshared_key_file']=str(ETC/'wg.psk')
    paths={}
    def rewrite(value):
        if isinstance(value,dict):
            for k,v in value.items():
                if k in ('certificate_path','key_path'):
                    if not isinstance(v,str) or not Path(v).is_absolute():raise ValueError('absolute TLS material path required')
                    if v not in paths:
                        if len(paths)>=4:raise ValueError('too many TLS files')
                        index=len(paths);target=str(ETC/f'tls-{index}.pem');paths[v]=f'/run/credentials/nextgen-engine.service/tls-{index}.pem';result[target]=safe_path(v).read_bytes()
                    value[k]=paths[v]
                else:rewrite(v)
        elif isinstance(value,list):
            for v in value:rewrite(v)
    rewrite(cfg)
    for i in range(4):result.setdefault(str(ETC/f'tls-{i}.pem'),b'')
    result[str(ETC/'engine.json')]=(json.dumps(cfg,indent=2)+'\n').encode()
    result[str(ETC/'site.json')]=(json.dumps(site,indent=2)+'\n').encode()
    credentials='\n'.join(f'LoadCredential=tls-{i}.pem:{ETC}/tls-{i}.pem' for i in range(4) if result[str(ETC/f'tls-{i}.pem')])
    for unit in UNITS:result['/etc/systemd/system/'+unit]=(ROOT/'systemd'/unit).read_bytes().replace(b'ENGINE_SHA256',a.engine_sha256.lower().encode()).replace(b'TLS_CREDENTIALS',credentials.encode())
    return result

def states():return {u:{k:run(['systemctl','is-'+k,'--quiet',u],False).returncode==0 for k in ('active','enabled')} for u in UNITS}
def application_pids():
    result=[]
    for pid in run(['ip','netns','pids','ngt-site-main']).stdout.split():
        try:groups=Path('/proc',pid,'cgroup').read_text().splitlines()
        except FileNotFoundError:continue
        # Only our root-owned recovery service may run a transient health ping.
        if '0::/system.slice/nextgen-site-watchdog.service' not in groups:result.append(pid)
    return result
def stop():
    for unit in UNITS[2:]:run(['systemctl','stop',unit],False)
    run(['systemctl','stop',UNITS[1]],False)
    r=run(['systemctl','stop',UNITS[0]],False)
    # An application inside a site must not be silently killed by updates.
    if Path('/run/netns/ngt-site-main').exists():
        if application_pids():raise ValueError('stop site applications before changing the installation')
        if (LIB/'site.py').exists():run(['python3',LIB/'site.py','remove','--name','ngt-site-main','--apply'])

def snapshot():
    backup=STATE/('backup-'+str(time.time_ns()));backup.mkdir(mode=0o700);records=[]
    for i,path in enumerate(FILES):
        p=safe_path(path);r=dict(path=path,index=i,existed=p.exists())
        if p.exists():
            shutil.copy2(p,backup/str(i));st=p.stat();r.update(mode=st.st_mode&0o777,uid=st.st_uid,gid=st.st_gid)
        records.append(r)
    j=dict(backup=str(backup),files=records,states=states(),previous=load(MARKER) if MARKER.exists() else None)
    atomic(JOURNAL,json.dumps(j).encode());return j

def restore(j):
    if {r['path'] for r in j['files']}!=set(FILES):raise ValueError('invalid journal allowlist')
    backup=Path(j['backup'])
    if backup.parent!=STATE or not backup.name.startswith('backup-'):raise ValueError('invalid journal backup')
    stop()
    for unit in UNITS:run(['systemctl','disable',unit],False)
    for r in j['files']:
        p=safe_path(r['path'])
        if r['existed']:
            if type(r['index'])!=int or not 0<=r['index']<len(FILES):raise ValueError('invalid backup index')
            atomic(p,safe_path(backup/str(r['index'])).read_bytes(),r['mode']);os.chown(p,r['uid'],r['gid'])
        else:p.unlink(missing_ok=True)
    if j['previous']:atomic(MARKER,json.dumps(j['previous']).encode())
    else:MARKER.unlink(missing_ok=True)
    run(['systemctl','daemon-reload'])
    for unit in UNITS:
        if j['states'][unit]['enabled']:run(['systemctl','enable',unit])
        if j['states'][unit]['active']:run(['systemctl','start',unit])
    if j['states'][UNITS[1]]['active']:health(wait=25)
    JOURNAL.unlink()

def validate_owned(old):
    if set(old.get('hashes',{})) not in (set(FILES),LEGACY_FILES,PRE_REDUNDANCY_FILES):raise ValueError('invalid ownership allowlist')
    for path,expected in old['hashes'].items():
        if digest(safe_path(path).read_bytes())!=expected:raise ValueError('managed file changed outside installer')

def health_once():
    for unit in UNITS[:3]:
        if unit.endswith('.timer') and not Path('/etc/systemd/system',unit).exists():continue
        run(['systemctl','is-active','--quiet',unit])
    run(['ip','-n','ngt-site-main','link','show','wg0'])
    group=run(['systemctl','show',UNITS[1],'-p','ControlGroup','--value']).stdout.strip()
    if not group.startswith('/system.slice/'):raise ValueError('unexpected engine cgroup')
    pids=set((Path('/sys/fs/cgroup')/group.lstrip('/')/'cgroup.procs').read_text().split())
    listeners=run(['ss','-H','-lntup']).stdout.splitlines()
    relay_path=ETC/'redundancy.json'
    if relay_path.exists() and load(relay_path).get('enabled'):
        port=load(relay_path)['listen'].rsplit(':',1)[1]
        if not any(line.startswith('udp ') and re.search(r':'+port+r'\s',line) and pids.intersection(re.findall(r'pid=(\d+)',line)) for line in listeners):raise ValueError('engine-owned redundancy listener not ready')
    for inbound in load(ETC/'engine.json')['inbounds']:
        protocols=['udp'] if inbound['type']=='hysteria2' else ['tcp'] if inbound['type']=='vless' else [inbound.get('network','')]
        if protocols==['']:protocols=['tcp','udp']
        for protocol in protocols:
            if not any(line.startswith(protocol+' ') and re.search(r':'+str(inbound['listen_port'])+r'\s',line) and pids.intersection(re.findall(r'pid=(\d+)',line)) for line in listeners):raise ValueError('engine-owned listener not ready')

def health(wait=0):
    end=time.monotonic()+wait;ready=None
    while True:
        try:
            health_once()
            if not wait:return
            if ready is None:ready=time.monotonic()
            if time.monotonic()-ready>=3:return
        except (ValueError,OSError,subprocess.SubprocessError):
            ready=None
            if time.monotonic()>=end:raise
        if time.monotonic()>=end:raise ValueError('engine readiness deadline')
        time.sleep(.5)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('install','update','uninstall','recover','status'));p.add_argument('--binary',type=Path);p.add_argument('--sha256');p.add_argument('--engine',type=Path);p.add_argument('--engine-sha256');p.add_argument('--engine-config',type=Path);p.add_argument('--site-config',type=Path);p.add_argument('--apply',action='store_true');a=p.parse_args()
    report=preflight()
    for tool in ('wg','ip','python3'):
        if not shutil.which(tool):p.error('missing prerequisite '+tool)
    if a.action=='status':
        health();print(json.dumps(dict(active=True,enabled=states(),namespace='ngt-site-main')));return
    files=None
    if a.action in ('install','update'):
        if not all((a.binary,a.sha256,a.engine,a.engine_sha256,a.engine_config,a.site_config)):p.error('both binaries, trusted SHA256 values, engine-config and site-config required')
        files=content(a)
    if not a.apply:print(json.dumps(dict(action=a.action,preflight=report,managed_paths=FILES,changes_applied=False),indent=2));return
    if os.geteuid()!=0:p.error('--apply requires root')
    secure_directory(STATE)
    import fcntl
    with (STATE/'lock').open('a') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if a.action=='recover':
            if JOURNAL.exists():restore(load(JOURNAL))
            print('recovery complete');return
        if JOURNAL.exists():raise ValueError('unfinished transaction; recover --apply first')
        old=load(MARKER) if MARKER.exists() else None
        if old:validate_owned(old)
        elif any(safe_path(path).exists() for path in FILES):raise ValueError('unmanaged target exists')
        if a.action=='uninstall' and not old:print('absent');return
        if old and any(safe_path(path).exists() for path in set(FILES)-set(old['hashes'])):raise ValueError('unmanaged new target exists')
        if old and files and old['hashes']==hashes(files):health();print('unchanged; engine and site active');return
        if old and a.action=='install':raise ValueError('changed configuration; use update')
        if not old and a.action=='update':raise ValueError('update requires owned installation')
        if Path('/run/netns/ngt-site-main').exists():
            if not old:raise ValueError('unmanaged site namespace exists')
            if application_pids():raise ValueError('stop site applications before update/uninstall')
        for path,mode in ((LIB,0o755),(ETC,0o700),(Path('/var/lib/nextgen-sites'),0o700),(Path('/var/lib/nextgen-stack-watchdog'),0o700),(Path('/run/netns'),0o755)):secure_directory(path,mode)
        os.chmod(ETC,0o700)
        journal=snapshot()
        try:
            stop()
            if a.action=='uninstall':
                for unit in UNITS:
                    if Path('/etc/systemd/system',unit).exists():run(['systemctl','disable',unit])
                for path in FILES:safe_path(path).unlink(missing_ok=True)
                MARKER.unlink();run(['systemctl','daemon-reload'])
            else:
                for path,data in files.items():atomic(path,data,0o755 if path.startswith(str(LIB)+'/') else 0o644 if path.endswith(('.service','.timer')) else 0o600)
                # Validate paths before systemd creates the private credential mount.
                check_data=files[str(ETC/'engine.json')].replace(b'/run/credentials/nextgen-engine.service/',str(ETC).encode()+b'/')
                fd,check_name=tempfile.mkstemp(dir=STATE,prefix='check-',suffix='.json')
                try:
                    with os.fdopen(fd,'wb') as handle:handle.write(check_data)
                    run([LIB/'nextgen-tunnel','engine-check','-binary',LIB/'sing-box','-sha256',a.engine_sha256,'-config',check_name,'-redundancy-config',ETC/'redundancy.json'])
                finally:Path(check_name).unlink(missing_ok=True)
                # The trusted digest is embedded in the fixed unit, never a shell command.
                unit=Path('/etc/systemd/system/nextgen-engine.service');unit_data=unit.read_bytes().replace(b'ENGINE_SHA256',a.engine_sha256.lower().encode());atomic(unit,unit_data,0o644);files[str(unit)]=unit_data
                run(['systemctl','daemon-reload'])
                for u in UNITS:
                    if not u.endswith('watchdog.service'):run(['systemctl','enable',u])
                    run(['systemctl','start',u])
                health(wait=25);atomic(MARKER,json.dumps(dict(hashes=hashes(files),backup=journal['backup'])).encode())
            JOURNAL.unlink()
        except BaseException:
            restore(journal);raise
        print('owned stack removed; protected backups retained' if a.action=='uninstall' else 'installed and enabled; remote data plane still requires acceptance')

if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,subprocess.SubprocessError) as exc:
        print('stack operation failed: '+str(exc),file=sys.stderr);raise SystemExit(1)
