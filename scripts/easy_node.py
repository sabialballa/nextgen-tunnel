#!/usr/bin/env python3
"""Root-only node operations shared by SSH and offline console pairing.

RPC stdout is a private SSH protocol, never a user log. Private WG, CA and
REALITY keys stay on the node that generated them; only WG public keys and
the minimal authenticated client export cross the encrypted SSH channel.
"""
import argparse,base64,contextlib,hashlib,ipaddress,json,os
from pathlib import Path
import re,socket,subprocess,sys,time,uuid
if __package__:
    from .menu import CORE_SHA,ENGINE_SHA,Menu,digest,safe_directory,verify_handshake
else:
    from menu import CORE_SHA,ENGINE_SHA,Menu,digest,safe_directory,verify_handshake

ROOT=Path(__file__).resolve().parents[1]
STATE=Path('/var/lib/nextgen-easy')
NATIVE=Path('/var/lib/nextgen-stack-installer')
TARGETS=('www.microsoft.com','www.cloudflare.com','github.com')
OVERLAYS=('gre','vxlan','ipip')

def write_json(path,data):
    path=Path(path)
    if path.is_symlink():raise ValueError('unsafe state symlink')
    if __package__:
        from .host_install import atomic
    else:
        from host_install import atomic
    atomic(path,(json.dumps(data,indent=2)+'\n').encode(),0o600)

def public_key(value):
    if not isinstance(value,str) or len(base64.b64decode(value,validate=True))!=32:raise ValueError('invalid WireGuard public key')
    return value

def client_export(value,listener):
    if not isinstance(value,dict):raise ValueError('invalid client export')
    if set(value)!=set(('server','uuid','server_name','public_key','short_id')):raise ValueError('invalid client export fields')
    if str(ipaddress.IPv4Address(value['server']))!=listener:raise ValueError('unexpected listener address')
    uuid.UUID(value['uuid'])
    if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}',value['server_name']) or not re.fullmatch(r'[0-9a-f]{16}',value['short_id']):raise ValueError('invalid client identity')
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}',value['public_key']) or len(base64.urlsafe_b64decode(value['public_key']+'='))!=32:raise ValueError('invalid REALITY public key')
    return dict(type='vless',tag='reality',server=listener,server_port=443,uuid=value['uuid'],flow='',packet_encoding='',tls=dict(enabled=True,server_name=value['server_name'],utls=dict(enabled=True,fingerprint='chrome'),reality=dict(enabled=True,public_key=value['public_key'],short_id=value['short_id'])))

def site_config(role,private,peer):
    if role not in ('listener','initiator'):raise ValueError('invalid role')
    public_key(peer);own,other=(1,2) if role=='listener' else (2,1)
    c=dict(name='ngt-site-main',private_key_file=str(private),peer_public_key=peer,addresses=[f'10.77.240.{own}/30',f'fd77:240::{own}/126'],remote_routes=[f'10.77.240.{other}/32',f'fd77:240::{other}/128'],listen_port=51850 if role=='listener' else 51860,mtu=1280)
    if role=='listener':c['redundant_listener_port']=51851
    else:c.update(endpoint='127.0.0.1:51811',persistent_keepalive=1)
    return c

def overlay_config(kind,role):
    if kind not in OVERLAYS or role not in ('listener','initiator'):raise ValueError('unknown overlay/role')
    own,other=(1,2) if role=='listener' else (2,1);subnet={'gre':250,'vxlan':251,'ipip':252}[kind]
    c=dict(name='ngo-'+kind,namespace='ngt-site-main',kind=kind,local=f'10.77.240.{own}',remote=f'10.77.240.{other}',address=f'10.78.{subnet}.{own}/30',mtu=1200)
    if kind=='vxlan':c.update(vni=10771,port=4789)
    return c

class Node:
    def __init__(self):
        if sys.platform!='linux' or os.geteuid()!=0:raise ValueError('Linux root required')
        safe_directory(STATE);self.path=STATE/'state.json';self.lock=None

    def __enter__(self):
        import fcntl
        fd=os.open(STATE/'node.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600);self.lock=os.fdopen(fd,'w')
        try:fcntl.flock(self.lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:self.lock.close();raise ValueError('Another easy installation is already running.')
        return self

    def __exit__(self,*_):self.lock.close()
    def state(self):
        if self.path.is_symlink():raise ValueError('unsafe state')
        return json.loads(self.path.read_text()) if self.path.exists() else None
    def save(self,s):write_json(self.path,s)

    def command(self,args,input=None,timeout=180):
        r=subprocess.run([str(x) for x in args],input=input,capture_output=True,timeout=timeout)
        if r.returncode:
            if __package__:
                from .host_install import atomic
            else:
                from host_install import atomic
            atomic(STATE/'last-error.log',r.stdout+b'\n'+r.stderr)
            detail=[line for line in r.stderr.decode(errors='replace').splitlines() if line.startswith('stack operation failed: nextgen-site.service:')]
            raise ValueError('Installation step failed; private log: '+str(STATE/'last-error.log')+(' | '+detail[-1] if detail else ''))
        return r.stdout.decode().strip()

    def metadata(self,data):
        state=self.state()
        if not state and ((NATIVE/'ownership.json').exists() or (NATIVE/'transaction.json').exists() or Path('/run/netns/ngt-site-main').exists()):raise ValueError('An existing installation was found and will not be replaced. Use the status or advanced management menu.')
        identity=Path('/etc/machine-id').read_text()+''.join(p.read_text() for p in sorted(Path('/etc/ssh').glob('ssh_host_*_key.pub')))
        route=json.loads(self.command(['ip','-j','route','get',str(ipaddress.IPv4Address(data['peer']))]))[0]
        connection=os.environ.get('SSH_CONNECTION','').split()
        return dict(host_id=hashlib.sha256(identity.encode()).hexdigest(),route_source=route.get('prefsrc',route.get('src')),observed_client=connection[0] if connection else None,state={k:state[k] for k in ['role','peer','pair_id','phase']} if state else None)

    def verify_files(self,s):
        if not isinstance(s,dict):raise ValueError('pair not prepared')
        for name,expected in s.get('files',{}).items():
            p=Path(name)
            if p.is_symlink() or not p.is_file() or digest(p)!=expected:raise ValueError('A generated file was modified outside the installer; replacement refused.')

    def record_files(self,s):
        s['files']={str(p):digest(p) for p in (STATE/'work').rglob('*') if p.is_file()};self.save(s)

    def owned_native(self,s):
        marker=NATIVE/'ownership.json'
        if not marker.exists():return False
        if marker.is_symlink():raise ValueError('unsafe native marker')
        owned=json.loads(marker.read_text())
        if not all(Path(p).is_file() and not Path(p).is_symlink() and digest(p)==v for p,v in owned['hashes'].items()):raise ValueError('The base installation has changed; stopped to preserve its files.')
        cfg=json.loads(Path('/etc/nextgen-stack/site.json').read_text())
        if digest('/etc/nextgen-stack/wg.key')!=digest(STATE/'work/wg/private.key') or cfg['peer_public_key']!=s.get('peer_public_key'):raise ValueError('The base installation does not belong to this pair.')
        return True

    def prepare(self,d):
        if d['role'] not in ('listener','initiator') or not re.fullmatch('[0-9a-f]{32}',d['pair_id']):raise ValueError('invalid role/pair')
        peer=str(ipaddress.IPv4Address(d['peer']));listener=str(ipaddress.IPv4Address(d['listener']))
        s=self.state()
        if s:
            if any(s[k]!=v for k,v in [('role',d['role']),('peer',peer),('pair_id',d['pair_id']),('listener',listener)]):raise ValueError('This server was prepared for a different pair or role; keys were not changed.')
            self.verify_files(s)
            if s['phase']!='preparing':return self.export(s)
        else:
            if (NATIVE/'ownership.json').exists() or Path('/run/netns/ngt-site-main').exists():raise ValueError('existing installation refused')
            if d['role']=='listener' and self.command(['ss','-Hlnt','( sport = :443 )']):raise ValueError('Port 443 is in use by another application; it was left unchanged.')
            if any((Path('/etc/systemd/system')/('nextgen-overlay-ngo-'+k+'.service')).exists() for k in OVERLAYS):raise ValueError('An existing overlay service was found.')
            runtime=Menu(root=ROOT).runtime()
            s=dict(version=1,role=d['role'],peer=peer,listener=listener,pair_id=d['pair_id'],phase='preparing',runtime=str(runtime),files={});self.save(s)
        runtime=Path(s['runtime'])
        if digest(runtime/'nextgen-tunnel')!=CORE_SHA or digest(runtime/'sing-box')!=ENGINE_SHA:raise ValueError('runtime changed')
        work=STATE/'work';safe_directory(work)
        if not (work/'wg').exists():self.command([sys.executable,ROOT/'scripts/site.py','keygen','--directory',work/'wg'])
        else:
            private=(work/'wg/private.key').read_bytes();expected=self.command(['wg','pubkey'],input=private)
            if expected!=(work/'wg/public.key').read_text().strip():raise ValueError('existing WG key pair differs')
        self.record_files(s)
        if d['role']=='listener':
            target=None
            for name in TARGETS:
                try:
                    addresses=socket.getaddrinfo(name,443,socket.AF_INET,socket.SOCK_STREAM)
                    for address in dict.fromkeys(v[4][0] for v in addresses):
                        try:verify_handshake(address,name,443);target=(name,address);break
                        except (OSError,ValueError):continue
                    if target:break
                except OSError:continue
            if not target:raise ValueError('No valid TLS 1.3 target is reachable from this server; the service was not installed.')
            if not s.get('profile_directory'):
                name='profile-'+uuid.uuid4().hex
                self.command([runtime/'nextgen-tunnel','engine-init','-dir',work/name,'-server-ip',listener,'-server-name',target[0]])
                s['profile_directory']=name;self.record_files(s)
            p=self.directory(s,'profile_directory')/'profile.json';profile=json.loads(p.read_text());profile.update(server_name=target[0],handshake_server=target[1],handshake_port=443);write_json(p,profile);self.record_files(s)
            name='plan-'+uuid.uuid4().hex
            self.command([runtime/'nextgen-tunnel','engine-plan','-profile',p,'-output',work/name]);s['plan_directory']=name
        s['phase']='prepared';self.record_files(s);return self.export(s)

    def export(self,s):
        result=dict(public_key=public_key((STATE/'work/wg/public.key').read_text().strip()),phase=s['phase'])
        if s['role']=='listener':
            p=json.loads((self.directory(s,'profile_directory')/'profile.json').read_text());result['client']=dict(server=s['listener'],uuid=p['uuid'],server_name=p['server_name'],public_key=p['reality_public_key'],short_id=p['short_id'])
        return result

    def directory(self,s,key):
        name=s[key]
        if not re.fullmatch(r'(profile|plan|config)-[0-9a-f]{32}',name):raise ValueError('invalid private directory')
        return STATE/'work'/name

    def configure(self,d):
        s=self.state();self.verify_files(s);public_key(d['peer_public_key'])
        sig=hashlib.sha256(json.dumps(d,sort_keys=True).encode()).hexdigest()
        if s.get('configuration_signature'):
            if s['configuration_signature']!=sig:raise ValueError('The peer key or config differs from the existing pair.')
            return dict(configured=True,unchanged=True)
        name='config-'+uuid.uuid4().hex;work=safe_directory(STATE/'work'/name)
        source=self.directory(s,'plan_directory')/'server.json' if s['role']=='listener' else work/'client-import.json'
        if s['role']=='initiator':write_json(source,dict(outbounds=[client_export(d['client'],s['listener'])]))
        self.command([sys.executable,ROOT/'scripts/stack_prepare.py','--role',s['role'],'--redundant','--source',source,'--output',work/'engine.json'])
        write_json(work/'site.json',site_config(s['role'],STATE/'work/wg/private.key',d['peer_public_key']))
        safe_directory(work/'overlays')
        for kind in OVERLAYS:write_json(work/'overlays'/(kind+'.json'),overlay_config(kind,s['role']))
        s.update(phase='configured',peer_public_key=d['peer_public_key'],configuration_signature=sig,configuration_directory=name);self.record_files(s);return dict(configured=True)

    def install(self,d):
        s=self.state();self.verify_files(s)
        if s['phase'] not in ('configured','installing','installed','ready'):raise ValueError('pair not configured')
        if self.owned_native(s):s['phase']='installed';self.save(s);return dict(installed=True,unchanged=True)
        if (NATIVE/'transaction.json').exists():
            journal=json.loads((NATIVE/'transaction.json').read_text())
            if s['phase']!='installing' or journal.get('previous'):raise ValueError('Unknown unfinished transaction; automatic recovery refused.')
            self.command([sys.executable,ROOT/'scripts/stack_install.py','recover','--apply'])
        runtime=Path(s['runtime']);config=self.directory(s,'configuration_directory');args=[sys.executable,ROOT/'scripts/stack_install.py','install','--binary',runtime/'nextgen-tunnel','--sha256',CORE_SHA,'--engine',runtime/'sing-box','--engine-sha256',ENGINE_SHA,'--engine-config',config/'engine.json','--site-config',config/'site.json']
        self.command(args);s.update(phase='installing',created_attempt=d['attempt']);self.save(s)
        self.command([*args,'--apply']);s['phase']='installed';self.save(s);return dict(installed=True)

    def overlays(self,d):
        s=self.state();self.verify_files(s)
        if not self.owned_native(s):raise ValueError('base installation missing')
        created=s.setdefault('overlay_attempts',{})
        for kind in OVERLAYS:
            marker=Path('/var/lib/nextgen-overlay-installer')/('ngo-'+kind+'.json')
            if not marker.exists():created[kind]=d['attempt'];self.save(s)
            self.command([sys.executable,ROOT/'scripts/overlay_service.py','install','--config',self.directory(s,'configuration_directory')/'overlays'/(kind+'.json'),'--apply'])
        s['phase']='ready';self.save(s);return dict(overlays=list(OVERLAYS))

    def probe(self,d):
        s=self.state();other=2 if s['role']=='listener' else 1;checks={};end=time.monotonic()+45
        targets=[('ipv4',f'10.77.240.{other}'),('ipv6',f'fd77:240::{other}')]
        if d.get('overlays'):targets += [(kind,f'10.78.{subnet}.{other}') for kind,subnet in [('gre',250),('vxlan',251),('ipip',252)]]
        for kind,target in targets:
            checks[kind]=False
            while time.monotonic()<end:
                r=subprocess.run(['ip','netns','exec','ngt-site-main','ping','-n','-c','1','-W','2',target],capture_output=True,timeout=5)
                if r.returncode==0:checks[kind]=True;break
                time.sleep(1)
        return dict(healthy=all(checks.values()),checks=checks)

    def rollback(self,d):
        s=self.state()
        if not s:return dict(rolled_back=False)
        for kind in reversed(OVERLAYS):
            if s.get('overlay_attempts',{}).get(kind)==d['attempt'] and (Path('/var/lib/nextgen-overlay-installer')/('ngo-'+kind+'.json')).exists():
                self.command([sys.executable,ROOT/'scripts/overlay_service.py','remove','--config',self.directory(s,'configuration_directory')/'overlays'/(kind+'.json'),'--apply']);s['overlay_attempts'].pop(kind);self.save(s)
        if s.get('created_attempt')==d['attempt']:
            if (NATIVE/'transaction.json').exists():self.command([sys.executable,ROOT/'scripts/stack_install.py','recover','--apply'])
            if self.owned_native(s):self.command([sys.executable,ROOT/'scripts/stack_install.py','uninstall','--apply'])
            s['phase']='configured';self.save(s);return dict(rolled_back=True,private_keys_retained=True)
        return dict(rolled_back=False,existing_installation_preserved=True)

    def dispatch(self,action,data):
        if action not in ('metadata','prepare','configure','install','overlays','probe','rollback'):raise ValueError('unknown operation')
        return getattr(self,action)(data)

def main():
    p=argparse.ArgumentParser();p.add_argument('action',choices=['serve']);p.parse_args()
    try:
        with Node() as node:
            print(json.dumps(dict(ok=True,ready=True)),flush=True)
            while True:
                line=sys.stdin.readline(1<<20)
                if not line:break
                try:
                    if not line.endswith('\n'):raise ValueError('RPC request too large')
                    request=json.loads(line)
                    if request['action']=='close':break
                    with contextlib.redirect_stdout(sys.stderr):result=node.dispatch(request['action'],request.get('data',{}))
                    print(json.dumps(dict(ok=True,data=result)),flush=True)
                except (ValueError,OSError,KeyError,subprocess.SubprocessError) as exc:print(json.dumps(dict(ok=False,error=str(exc))),flush=True)
    except (ValueError,OSError) as exc:print(json.dumps(dict(ok=False,error=str(exc))),flush=True);raise SystemExit(1)
if __name__=='__main__':main()
