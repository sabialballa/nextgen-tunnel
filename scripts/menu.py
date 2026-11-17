#!/usr/bin/env python3
"""Interactive Linux entry point; delegate mutations to the owned installers."""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
RELEASE='https://github.com/sabialballa/nextgen-tunnel/releases/download/v0.3.0-rc3/'
BUNDLE='nextgen-tunnel-0.3.0-rc3-linux-amd64-full.tar.gz'
BUNDLE_SHA='85ac53b1e0e94e15ad53a92c2d33490321c4793aae8c52075de14b314106cc4f'
CORE_SHA='96cec972279a1d7a02f13aed4dd6fd3029b581576edd8f48bc598abb9726433f'
ENGINE_SHA='606f883d1aa3c624f38aa3f99bf0df02e3999f9aa0ff5826e0dd9c1b9f964baf'
BUNDLE_BYTES=109378369
UNITS=['nextgen-engine.service','nextgen-site.service','nextgen-site-watchdog.timer']+['nextgen-overlay-ngo-'+k+'.service' for k in ['gre','vxlan','ipip']]

def user_id():return os.geteuid() if hasattr(os,'geteuid') else -1

def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda:f.read(1<<20),b''):h.update(chunk)
    return h.hexdigest()

def verify_handshake(address,name,port):
    context=ssl.create_default_context();context.minimum_version=ssl.TLSVersion.TLSv1_3
    with socket.create_connection((address,port),timeout=8) as raw:
        with context.wrap_socket(raw,server_hostname=name) as peer:
            if peer.version()!='TLSv1.3':raise ValueError('The handshake target must support valid TLS 1.3.')

def safe_directory(path):
    path=Path(path).expanduser().absolute()
    for parent in [path,*path.parents]:
        if parent.is_symlink():raise ValueError('The data path must not contain symlinks.')
    path.mkdir(mode=0o700,parents=True,exist_ok=True)
    st=path.stat()
    if st.st_uid!=user_id() or st.st_mode&0o077:raise ValueError('The data directory must be owned by you with mode 700: '+str(path))
    return path

def progress_line(message,finish=False):
    """Update one terminal row; keep piped output readable as normal lines."""
    if sys.stdout.isatty():print('\r\033[2K'+message,end='\n' if finish else '',flush=True)
    else:print(message,flush=True)

def fetch_bundle(cache):
    """Keep partial bytes for a bounded, visible, resumable HTTPS download."""
    local=cache/BUNDLE;partial=cache/(BUNDLE+'.part')
    for path in (local,partial):
        if path.is_symlink():raise ValueError('Unsafe download cache path.')
    if local.is_file():
        print('Using uploaded bundle: '+str(local),flush=True)
        return local
    offset=partial.stat().st_size if partial.exists() else 0
    if offset>BUNDLE_BYTES:raise ValueError('Partial download exceeds the expected size; check '+str(partial))
    if offset==BUNDLE_BYTES:return partial
    progress_line(f'Downloading full Linux x64 bundle: {100*offset/BUNDLE_BYTES:.1f}% | {offset/1024**2:.1f}/{BUNDLE_BYTES/1024**2:.1f} MiB | connecting...')
    headers={'User-Agent':'nextgen-menu/2','Accept-Encoding':'identity'}
    if offset:headers['Range']=f'bytes={offset}-'
    started=last=time.monotonic();received=0
    try:
        with urllib.request.urlopen(urllib.request.Request(RELEASE+BUNDLE,headers=headers),timeout=15) as response:
            status=getattr(response,'status',200)
            if status==206:
                expected=f'bytes {offset}-'
                content_range=response.headers.get('Content-Range','')
                if not content_range.startswith(expected) or not content_range.endswith('/'+str(BUNDLE_BYTES)):raise ValueError('Invalid resume response; download refused.')
            elif status==200:
                if offset:progress_line('Server did not support resume; restarting this download.')
                offset=0
            else:raise ValueError('Unexpected download HTTP status: '+str(status))
            with partial.open('ab' if offset else 'wb') as out:
                read=getattr(response,'read1',response.read)
                while True:
                    if time.monotonic()-started>=180:raise TimeoutError('Download reached its 3-minute limit.')
                    chunk=read(64*1024)
                    if not chunk:break
                    offset+=len(chunk);received+=len(chunk)
                    if offset>BUNDLE_BYTES:raise ValueError('Download exceeds the expected bundle size.')
                    out.write(chunk)
                    now=time.monotonic()
                    if now-last>=2:
                        progress_line(f'Download progress: {100*offset/BUNDLE_BYTES:.1f}% | {offset/1024**2:.1f}/{BUNDLE_BYTES/1024**2:.1f} MiB | {received/1024/max(now-started,0.01):.0f} KiB/s');last=now
        if offset<BUNDLE_BYTES:raise ValueError('Incomplete download; SHA256 cannot be verified yet. Run this option again to resume.')
        progress_line(f'Download progress: 100.0% | {BUNDLE_BYTES/1024**2:.1f}/{BUNDLE_BYTES/1024**2:.1f} MiB | complete')
    except OSError as exc:
        raise ValueError('Download stopped: '+str(exc)+'. Run this option again to resume. If GitHub is unreachable, download '+RELEASE+BUNDLE+' on another network and upload it to '+str(local)) from None
    finally:
        if sys.stdout.isatty():print(flush=True)
    print('Download complete. Checking SHA256 and extracting the bundle...',flush=True)
    return partial

def download_bundle(cache):
    """Pinned archive plus manifest, safe extraction, publish cache atomically."""
    if __package__:
        from .verify_bundle import verify
    else:
        from verify_bundle import verify
    cache=safe_directory(cache);ready=cache/'runtime-0.3.0-rc3'
    if ready.exists():
        if ready.is_symlink() or digest(ready/'bin/nextgen-tunnel')!=CORE_SHA or digest(ready/'bin/sing-box')!=ENGINE_SHA:raise ValueError('The cached bundle has changed; check the cache directory.')
        return ready
    # Also used outside the node installer (menu option 9): serialize this cache.
    lock_path=cache/'download.lock'
    if lock_path.is_symlink():raise ValueError('Unsafe download lock.')
    with lock_path.open('a+b') as lock:
        if os.name=='posix':
            import fcntl
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise ValueError('Another bundle download is running; retry after it finishes.')
        return _download_bundle_locked(cache,ready)

def _download_bundle_locked(cache,ready):
    if ready.exists():return ready
    archive=fetch_bundle(cache)
    if archive.stat().st_size>BUNDLE_BYTES:raise ValueError('Bundle exceeds the expected size.')
    with tempfile.TemporaryDirectory(prefix='download-',dir=cache) as temp:
        work=Path(temp)
        if digest(archive)!=BUNDLE_SHA:
            if archive==cache/(BUNDLE+'.part'):archive.unlink()
            raise ValueError('Bundle SHA256 mismatch; execution refused. Retry the download or replace the uploaded archive.')
        verify(archive)
        extracted=work/'runtime';extracted.mkdir(mode=0o700)
        with tarfile.open(archive,'r:gz') as bundle:
            for member in bundle:
                parts=Path(member.name).parts[1:];target=extracted.joinpath(*parts)
                target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                with bundle.extractfile(member) as src,target.open('xb') as dst:shutil.copyfileobj(src,dst)
                target.chmod(0o755 if parts[0]=='bin' else 0o600)
        if digest(extracted/'bin/nextgen-tunnel')!=CORE_SHA or digest(extracted/'bin/sing-box')!=ENGINE_SHA:raise ValueError('Bundle binaries do not match the tested version.')
        extracted.rename(ready)
    return ready

class Menu:
    def __init__(self,root=ROOT,ask=None):
        self.root=Path(root);self.ask=ask or input
        self.home=Path('/var/lib/nextgen-menu') if user_id()==0 else Path.home()/'.local/share/nextgen-menu'
        self.cache=Path('/var/cache/nextgen-menu') if user_id()==0 else Path.home()/'.cache/nextgen-menu'

    def prompt(self,text,default=''):
        answer=self.ask(text+(f' [{default}]' if default else '')+': ').strip()
        return answer or str(default)

    def path(self,text,default='',new=False):
        value=self.prompt(text,default)
        if not value:raise ValueError('No path entered.')
        p=Path(value).expanduser().absolute()
        if new:
            if p.exists() or p.is_symlink():raise ValueError('The new path must not already exist.')
        elif not p.is_file():raise ValueError('File not found: '+str(p))
        return p

    def root_required(self):
        if user_id()!=0:raise ValueError('Run this option as root or with sudo.')

    def command(self,args,check=True,timeout=180,quiet=False):
        result=subprocess.run([str(x) for x in args],timeout=timeout,capture_output=quiet,text=quiet)
        if check and result.returncode:
            if quiet:print((result.stdout+result.stderr)[-4000:])
            raise ValueError('Operation failed; check the output above.')
        return result.returncode

    def script(self,name,*args):return [sys.executable,str(self.root/'scripts'/name),*map(str,args)]

    def approve(self,description):
        print('\n'+description)
        return self.prompt('Type yes to apply; press Enter to cancel').casefold() in ('yes','\u0628\u0644\u0647')

    def apply(self,args,description):
        self.root_required();self.command(args,quiet=True)
        if self.approve(description):self.command([*args,'--apply'])
        else:print('No changes applied.')

    def runtime(self):
        if platform.machine().lower() not in ('x86_64','amd64'):raise ValueError('The prebuilt bundle supports Linux x64 only; see the build guide for ARM.')
        installed=Path('/usr/local/lib/nextgen-stack')
        if all((installed/name).is_file() and digest(installed/name)==sha for name,sha in [('nextgen-tunnel',CORE_SHA),('sing-box',ENGINE_SHA)]):return installed
        return download_bundle(self.cache)/'bin'

    def prepare(self):
        print("\n1) Create listener profile and engine keys\n2) Create CA and standalone core keys\n3) Create carrier from an existing engine config\n4) Generate WireGuard keys on this server\n5) Create this side's Site-to-Site config\n0) Back")
        choice=self.prompt('Select an option')
        if choice=='0':return
        self.root_required();home=safe_directory(self.home)
        if choice=='1':
            binary=self.runtime()/'nextgen-tunnel';directory=self.path('New private profile directory',home/'profile',new=True)
            ip=str(ipaddress.IPv4Address(self.prompt('Listener public IPv4')));name=self.prompt('Handshake target TLS/SNI hostname')
            if not name:raise ValueError('A TLS/SNI hostname is required.')
            handshake=str(ipaddress.IPv4Address(self.prompt('Handshake target IP with valid TLS 1.3')))
            if ipaddress.ip_address(handshake).is_loopback:raise ValueError('The handshake target must not be a loopback address.')
            port=int(self.prompt('Handshake target TLS port','443'))
            if not 1<=port<=65535:raise ValueError('Invalid port.')
            print('Verifying the target certificate, hostname and TLS 1.3...');verify_handshake(handshake,name,port)
            self.command([binary,'engine-init','-dir',directory,'-server-ip',ip,'-server-name',name])
            profile=directory/'profile.json'
            original=json.loads(profile.read_text())
            key=next((k for k in original if k in ('handshake_server','reality_handshake_server')),None)
            if not key:raise ValueError('Unknown handshake field in this core version; configure profile.json using the guide.')
            original[key]=handshake;original['handshake_port']=port;profile.write_text(json.dumps(original,indent=2)+'\n');profile.chmod(0o600)
            output=directory/'configs';self.command([binary,'engine-plan','-profile',profile,'-output',output])
            print('Profile created in '+str(directory)+'. Securely transfer only client files and the public CA; do not transfer CA.key or the server private key.')
            print('Target TLS and hostname verified; an actual two-server connectivity test is still required. Guide: https://github.com/sabialballa/nextgen-tunnel/blob/main/docs/engine-site.md')
        elif choice=='2':
            binary=self.runtime()/'nextgen-tunnel';directory=self.path('New PKI directory',home/'pki',new=True)
            self.command([binary,'pki','-dir',directory,'-server-name',self.prompt('Server TLS name','tunnel.internal'),'-client-name',self.prompt('Client name','entry')])
        elif choice=='3':
            role={'1':'listener','2':'initiator'}.get(self.prompt('Role: 1=listener, 2=initiator'))
            if not role:raise ValueError('Invalid role.')
            source=self.path('Existing server.json or client.json path');target=self.path('New carrier config file',home/'carrier.json',new=True)
            port=int(self.prompt('Listener public TCP port; use the same port on both sides','443'))
            if not 1<=port<=65535:raise ValueError('Invalid port.')
            self.command(self.script('stack_prepare.py','--role',role,'--redundant','--public-port',port,'--source',source,'--output',target))
            print('Carrier created. Prepare site.json and the peer public key using the engine/site guide before installation.')
        elif choice=='4':
            directory=self.path('New WireGuard key directory',home/'wg',new=True)
            self.command(self.script('site.py','keygen','--directory',directory));print('Exchange only public.key with the peer.')
        elif choice=='5':self.site_config(home)
        else:print('Invalid option.')

    def site_config(self,home):
        role=self.prompt('Role: 1=listener, 2=initiator')
        if role not in ('1','2'):raise ValueError('Invalid role.')
        own='1' if role=='1' else '2';other='2' if own=='1' else '1'
        private=self.path("This server's WireGuard private key file",home/'wg/private.key')
        peer=self.prompt('Peer WireGuard public key')
        if len(base64.b64decode(peer,validate=True))!=32:raise ValueError('The public key must be 32 bytes encoded as base64.')
        local4=str(ipaddress.IPv4Interface(self.prompt('Local IPv4 address',f'10.77.240.{own}/30')))
        remote4=str(ipaddress.IPv4Address(self.prompt('Peer IPv4 address',f'10.77.240.{other}')))
        local6=str(ipaddress.IPv6Interface(self.prompt('Local IPv6 address',f'fd77:240::{own}/126')))
        remote6=str(ipaddress.IPv6Address(self.prompt('Peer IPv6 address',f'fd77:240::{other}')))
        cfg=dict(name='ngt-site-main',private_key_file=str(private),peer_public_key=peer,addresses=[local4,local6],remote_routes=[remote4+'/32',remote6+'/128'],listen_port=51850 if role=='1' else 51860,mtu=1280)
        if role=='1':cfg['redundant_listener_port']=51851
        else:cfg.update(endpoint='127.0.0.1:51811',persistent_keepalive=1)
        target=self.path('New site config file',home/'site.json',new=True);safe_directory(target.parent)
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as out:json.dump(cfg,out,indent=2)
        print('Local config created: '+str(target)+'; repeat these steps on the other server with the opposite role and independent keys.')

    def stack(self):
        self.root_required()
        print('\n1) Install engine/site\n2) Update\n3) Recover an unfinished transaction\n0) Back')
        choice=self.prompt('Select an option');action={'1':'install','2':'update','3':'recover'}.get(choice)
        if not action:return
        args=self.script('stack_install.py',action)
        if action!='recover':
            binary=self.runtime();engine=self.path('Existing carrier/engine config file','/etc/nextgen-stack/engine.json');site=self.path('Existing site.json file','/etc/nextgen-stack/site.json')
            args+=['--binary',str(binary/'nextgen-tunnel'),'--sha256',CORE_SHA,'--engine',str(binary/'sing-box'),'--engine-sha256',ENGINE_SHA,'--engine-config',str(engine),'--site-config',str(site)]
        self.apply(args,"This changes only the managed engine/site installation. Each server requires its own side's config.")

    def overlays(self):
        self.root_required();kind={'1':'gre','2':'vxlan','3':'ipip'}.get(self.prompt('Tunnel type: 1=GRE, 2=VXLAN, 3=IPIP'))
        if not kind:raise ValueError('Invalid tunnel type.')
        action={'1':'install','2':'status','3':'remove'}.get(self.prompt('1=Install, 2=Status, 3=Remove'))
        if not action:raise ValueError('Invalid option.')
        installed=Path('/etc/nextgen-overlays')/('ngo-'+kind+'.json')
        if action=='install' and not installed.exists():
            local=str(ipaddress.IPv4Address(self.prompt('Local private IP on wg0','10.77.240.1')));remote=str(ipaddress.IPv4Address(self.prompt('Peer private IP on wg0','10.77.240.2')))
            side=self.prompt('Local side: 1 or 2','1' if local.endswith('.1') else '2')
            if side not in ('1','2'):raise ValueError('Side must be 1 or 2.')
            subnet={'gre':250,'vxlan':251,'ipip':252}[kind]
            address=str(ipaddress.IPv4Interface(self.prompt('New overlay address',f'10.78.{subnet}.{side}/30')))
            cfg=dict(name='ngo-'+kind,namespace=self.prompt('Existing site namespace','ngt-site-main'),kind=kind,local=local,remote=remote,address=address,mtu=1200)
            if kind=='vxlan':cfg.update(vni=10771,port=4789)
            if __package__:
                from .overlay import validate
            else:
                from overlay import validate
            validate(cfg);directory=safe_directory(self.home/'overlays')
            fd,filename=tempfile.mkstemp(prefix=kind+'-',suffix='.json',dir=directory)
            with os.fdopen(fd,'w') as out:json.dump(cfg,out)
            config=Path(filename)
        else:config=self.path('Config file for this tunnel',installed)
        args=self.script('overlay_service.py',action,'--config',config)
        if action=='status':self.command(args)
        else:self.apply(args,'Tunnel '+kind.upper()+(' will be installed.' if action=='install' else ' and the service owned by this config will be removed.'))

    def status(self):
        print('\nService status:')
        names=['TCP engine','Private site','Automatic recovery','GRE','VXLAN','IPIP','Standalone core']
        for unit,label in zip([*UNITS,'nextgen-tunnel.service'],names):
            result=subprocess.run(['systemctl','is-active',unit],capture_output=True,text=True,timeout=5)
            state=result.stdout.strip();print(label+': '+{'active':'Active','inactive':'Inactive','failed':'Failed','unknown':'Not installed'}.get(state,state or 'Unknown'))

    def test(self):
        print('\n1) Probe core paths using client.json\n2) Run a bounded site/overlay ping\n0) Back')
        choice=self.prompt('Select an option')
        if choice=='1':self.command([self.runtime()/'nextgen-tunnel','probe','-config',self.path('client.json file')])
        elif choice=='2':
            self.root_required();namespace=self.prompt('namespace','ngt-site-main')
            import re
            if not re.fullmatch(r'ngt-site-[a-z0-9_-]{1,18}',namespace):raise ValueError('Invalid namespace.')
            target=str(ipaddress.ip_address(self.prompt('Target private IP','10.78.252.2')))
            self.command(['ip','netns','exec',namespace,'ping','-n','-c','5','-W','2',target],timeout=20)

    def core(self):
        self.root_required();print('\n1) Install standalone core\n2) Update\n3) Recover transaction\n4) Uninstall standalone core\n0) Back')
        action={'1':'install','2':'update','3':'recover','4':'uninstall'}.get(self.prompt('Select an option'))
        if not action:return
        args=self.script('host_install.py',action)
        if action in ('install','update'):args+=['--binary',str(self.runtime()/'nextgen-tunnel'),'--sha256',CORE_SHA,'--config',str(self.path("This side's server.json or client.json config"))]
        self.apply(args,'This option manages only the standalone nextgen-tunnel service: '+action)

    def easy(self):
        self.root_required()
        print('\nAutomatic installation on both servers; root SSH access to the peer is required.\nKeys and configs are generated and exchanged automatically; no manual JSON editing.\nSSH may ask for a password or host fingerprint confirmation; passwords are not stored.')
        role={'1':'listener','2':'initiator'}.get(self.prompt('Local server role: 1=Iran / listener, 2=Outside Iran / initiator'))
        if not role:raise ValueError('Invalid role.')
        peer=str(ipaddress.IPv4Address(self.prompt('Peer IPv4 address')))
        if __package__:
            from .easy_install import install_pair
        else:
            from easy_install import install_pair
        install_pair(role,peer,self.root)

    def console_pair(self):
        self.root_required()
        if __package__:
            from .code_install import run
        else:
            from code_install import run
        run(ask=self.ask)

    def run(self):
        actions={'1':self.easy,'2':self.prepare,'3':self.stack,'4':self.overlays,'5':self.status,'6':self.test,'7':lambda:self.command(['journalctl','--no-pager','-n','60',*sum((['-u',u] for u in UNITS),[])],check=False),'8':self.core,'9':lambda:print('Prebuilt binaries: '+str(self.runtime()))}
        actions['10']=self.console_pair
        while True:
            print('\n=== NEXTGEN TUNNEL | Management Menu ===\n1) Easy install on both servers over SSH\n2) Advanced: prepare keys and configs\n3) Advanced: install / update engine and Site-to-Site\n4) Manage GRE / VXLAN / IPIP\n5) Service status\n6) Test connectivity\n7) View logs\n8) Manage standalone core\n9) Download / verify prebuilt bundle\n10) Install separately without SSH: pairing codes\n0) Exit')
            try:
                choice=self.prompt('Select an option')
                if choice=='0':return
                if choice not in actions:print('Invalid option.');continue
                actions[choice]()
            except (EOFError,KeyboardInterrupt):print('\nExiting.');return
            except (ValueError,OSError,subprocess.SubprocessError,KeyError) as exc:print('Error: '+str(exc))

def main():
    parser=argparse.ArgumentParser(description='Nextgen Tunnel installation and management menu for Linux');parser.parse_args()
    if sys.platform!='linux':raise SystemExit('Run this menu on a Linux server.')
    Menu().run()
if __name__=='__main__':main()
