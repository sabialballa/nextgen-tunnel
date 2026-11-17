#!/usr/bin/env python3
"""Two configuration inputs; authenticate to the other root account with OpenSSH.

No sshpass, password files, copied SSH private keys or unauthenticated enrollment.
"""
import argparse,contextlib,hashlib,io,ipaddress,json,os
from pathlib import Path,PurePosixPath
import platform,queue,shlex,shutil,subprocess,sys,tarfile,tempfile,threading,uuid
if __package__:
    from .easy_node import Node
else:
    from easy_node import Node

ROOT=Path(__file__).resolve().parents[1]
DEPENDENCIES={'ssh':'openssh-client','curl':'curl','ip':'iproute2','ss':'iproute2','wg':'wireguard-tools','openssl':'openssl'}
PRELUDE=r'''set -eu
[ "$(id -u)" = 0 ] || { echo 'Root SSH access is required.' >&2; exit 1; }
[ "$(uname -s)" = Linux ] && [ "$(uname -m)" = x86_64 ] || { echo 'Linux amd64 is required.' >&2; exit 1; }
if [ -e /var/lib/nextgen-stack-installer/ownership.json ] && [ ! -e /var/lib/nextgen-easy/state.json ]; then
    echo 'Existing installation was preserved; use the advanced management menu.' >&2; exit 1
fi
missing=''
for item in python3:python3 curl:curl ip:iproute2 ss:iproute2 wg:wireguard-tools openssl:openssl; do
    command -v "${item%%:*}" >/dev/null 2>&1 || missing="$missing ${item#*:}"
done
[ -s /etc/ssl/certs/ca-certificates.crt ] || missing="$missing ca-certificates"
if [ -n "$missing" ]; then
    command -v apt-get >/dev/null || { echo 'Install Python3, iproute2, wireguard-tools, curl and CA certificates first.' >&2; exit 1; }
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-upgrade --no-install-recommends $missing
fi
python3 -c 'import sys; assert sys.version_info >= (3,10), "Python3.10+ required"'
'''
UNPACK=r'''import hashlib,io,json,os,pathlib,sys,tarfile,tempfile
base=pathlib.Path('/var/lib/nextgen-easy')
if any(p.is_symlink() for p in [base,*base.parents]):raise ValueError('unsafe source root')
base.mkdir(mode=0o700,exist_ok=True)
if base.stat().st_uid!=0 or base.stat().st_mode&0o077:raise ValueError('unsafe source permissions')
raw=sys.stdin.buffer.read(4*1024**2+1)
if len(raw)>4*1024**2:raise ValueError('source too large')
entries={}
with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as t:
 for m in t:
  p=pathlib.PurePosixPath(m.name)
  if not m.isfile() or m.size<0 or m.size>1024**2 or len(entries)>=100 or len(p.parts)!=2 or p.parts[0] not in ['scripts','systemd'] or p.suffix not in ['.py','.service','.timer'] or '..' in p.parts or m.name.startswith('/') or '\\' in m.name or m.name in entries:raise ValueError('unsafe source member')
  entries[m.name]=t.extractfile(m).read()
if sum(map(len,entries.values()))>4*1024**2:raise ValueError('expanded source too large')
manifest={p:hashlib.sha256(v).hexdigest() for p,v in entries.items()}
identity=hashlib.sha256(json.dumps(manifest,sort_keys=True).encode()).hexdigest()
target=base/('source-'+identity)
if target.exists():
 if target.is_symlink() or any((target/p).is_symlink() or not (target/p).is_file() or hashlib.sha256((target/p).read_bytes()).hexdigest()!=s for p,s in manifest.items()):raise ValueError('source differs from owned copy')
else:
 with tempfile.TemporaryDirectory(prefix='source-upload-',dir=base) as work:
  stage=pathlib.Path(work)/'source';stage.mkdir(mode=0o700)
  for p,v in entries.items():
   q=stage/p;q.parent.mkdir(mode=0o700,exist_ok=True);q.write_bytes(v);q.chmod(0o600)
  stage.rename(target)
print(json.dumps({'source':str(target),'identity':identity}))
'''

def source_archive(root):
    names=['easy_install.py','easy_node.py','menu.py','verify_bundle.py','host_install.py','stack_install.py','stack_prepare.py','site.py','site_watchdog.py','overlay.py','overlay_service.py']
    files=[Path('scripts')/n for n in names]+[p.relative_to(root) for p in (root/'systemd').glob('*') if p.suffix in ('.service','.timer')]
    out=io.BytesIO()
    with tarfile.open(fileobj=out,mode='w:gz') as t:
        for path in sorted(files):
            source=root/path
            if source.is_symlink():raise ValueError('unsafe source symlink')
            data=source.read_bytes();m=tarfile.TarInfo(path.as_posix());m.size=len(data);m.mode=0o600;t.addfile(m,io.BytesIO(data))
    return out.getvalue()

def dependencies():
    missing=sorted({pkg for tool,pkg in DEPENDENCIES.items() if not shutil.which(tool)})
    if not Path('/etc/ssl/certs/ca-certificates.crt').is_file():missing.append('ca-certificates')
    if missing:
        if not shutil.which('apt-get'):raise ValueError('Python3, curl, OpenSSH, iproute2 and wireguard-tools are required.')
        print('Installing missing tools from the system repository; no full system upgrade...')
        subprocess.run(['apt-get','update','-qq'],check=True,timeout=300)
        subprocess.run(['apt-get','install','-y','--no-upgrade','--no-install-recommends',*missing],check=True,timeout=300,env={**os.environ,'DEBIAN_FRONTEND':'noninteractive'})

class SSH:
    def __init__(self,peer,root):self.peer=peer;self.root=root;self.temp=None;self.process=None
    def options(self):return ['ssh','-S',str(Path(self.temp.name)/'ssh'),'--',self.peer]
    def run(self,command,input=None,timeout=600):
        r=subprocess.run([*self.options(),command],input=input,capture_output=True,timeout=timeout)
        if r.returncode:raise ValueError('SSH step failed: '+r.stderr.decode(errors='replace')[-1000:])
        return r.stdout
    def __enter__(self):
        self.temp=tempfile.TemporaryDirectory(prefix='ngt-ssh-')
        try:
            # Set root on the client command, never alter the peer's SSH server.
            self.peer='root@'+self.peer
            subprocess.run(['ssh','-M','-N','-f','-S',str(Path(self.temp.name)/'ssh'),'-o','ControlPersist=60','-o','StrictHostKeyChecking=ask','-o','ConnectTimeout=15','-o','ServerAliveInterval=15','--',self.peer],check=True)
            self.run('sh -c '+shlex.quote(PRELUDE))
            result=json.loads(self.run('python3 -c '+shlex.quote(UNPACK),input=source_archive(self.root)).decode())
            source=result['source']
            if not source.startswith('/var/lib/nextgen-easy/source-') or len(result['identity'])!=64 or source.rsplit('-',1)[-1]!=result['identity']:raise ValueError('invalid remote source identity')
            cmd=shlex.join(['python3','-X','utf8','-B',source+'/scripts/easy_node.py','serve'])
            self.process=subprocess.Popen([*self.options(),cmd],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8',bufsize=1)
            self.messages=queue.Queue()
            def reader():
                try:
                    for line in self.process.stdout:self.messages.put(json.loads(line))
                except (ValueError,OSError):pass
                finally:self.messages.put(None)
            def drain():
                for line in self.process.stderr:
                    if line.startswith('Downloading full Linux x64 bundle'):print('Peer: '+line.strip(),flush=True)
            threading.Thread(target=reader,daemon=True).start();threading.Thread(target=drain,daemon=True).start()
            ready=self.messages.get(timeout=30)
            if not ready or not ready.get('ready'):raise ValueError((ready or {}).get('error','Invalid response from the peer installer.'))
            return self
        except BaseException:self.__exit__();raise
    def call(self,action,data):
        self.process.stdin.write(json.dumps(dict(action=action,data=data))+'\n');self.process.stdin.flush()
        try:answer=self.messages.get(timeout=900)
        except queue.Empty:raise ValueError('Peer installer response timed out; private installation state was retained.')
        if not answer or not answer.get('ok'):raise ValueError((answer or {}).get('error','Connection to the peer installer was lost.'))
        return answer['data']
    def __exit__(self,*_):
        if self.process:
            if self.process.poll() is None:
                try:self.process.stdin.write('{"action":"close"}\n');self.process.stdin.flush();self.process.wait(timeout=5)
                except (OSError,subprocess.TimeoutExpired):self.process.terminate()
            for stream in [self.process.stdin,self.process.stdout,self.process.stderr]:
                try:stream.close()
                except (OSError,ValueError):pass
        if self.temp:
            try:subprocess.run(['ssh','-S',str(Path(self.temp.name)/'ssh'),'-O','exit','--',self.peer],capture_output=True,timeout=10)
            except (OSError,subprocess.SubprocessError):pass
            finally:self.temp.cleanup()

class Local:
    def __init__(self,node):self.node=node
    def call(self,action,data):return self.node.dispatch(action,data)

def pair_identity(local,remote,role):
    if local['host_id']==remote['host_id']:raise ValueError('The peer IP points to this server; installation stopped.')
    listener,initiator=(local,remote) if role=='listener' else (remote,local)
    return hashlib.sha256(('nextgen-easy-1:'+listener['host_id']+':'+initiator['host_id']).encode()).hexdigest()[:32]

def configure_pair(local,remote,local_meta,remote_meta,role,peer):
    other='initiator' if role=='listener' else 'listener'
    own=local_meta.get('route_source')
    if not own or not ipaddress.ip_address(own).is_global:own=remote_meta.get('observed_client') or own
    own=str(ipaddress.IPv4Address(own))
    if ipaddress.ip_address(own).is_loopback:raise ValueError("Could not automatically detect this server's reachable IP.")
    listener=own if role=='listener' else peer;pair=pair_identity(local_meta,remote_meta,role)
    shared=dict(pair_id=pair,listener=listener)
    print('Generating or checking independent server keys and selecting a valid TLS target...',flush=True)
    a=local.call('prepare',dict(shared,role=role,peer=peer));b=remote.call('prepare',dict(shared,role=other,peer=own))
    export=a.get('client') if role=='listener' else b.get('client')
    local.call('configure',dict(peer_public_key=b['public_key'],**({'client':export} if role=='initiator' else {})))
    remote.call('configure',dict(peer_public_key=a['public_key'],**({'client':export} if other=='initiator' else {})))
    return pair

def install_pair(role,peer,root=ROOT):
    peer=str(ipaddress.IPv4Address(peer))
    if role not in ('listener','initiator') or ipaddress.ip_address(peer).is_loopback or ipaddress.ip_address(peer).is_unspecified or ipaddress.ip_address(peer).is_multicast:raise ValueError('Invalid role or peer IP.')
    if sys.platform!='linux' or os.geteuid()!=0 or platform.machine()!='x86_64':raise ValueError('Easy installation requires Linux x64 and root.')
    with Node() as node:
        if not node.state() and (Path('/var/lib/nextgen-stack-installer/ownership.json').exists() or Path('/run/netns/ngt-site-main').exists()):raise ValueError('Existing installation preserved; use the status or advanced management menu.')
        dependencies();local=Local(node)
        print('Connecting to the peer over SSH; SSH may ask for a host fingerprint confirmation or password...',flush=True)
        with SSH(peer,Path(root)) as remote:
            a=local.call('metadata',dict(peer=peer));b=remote.call('metadata',dict(peer=a.get('route_source') or peer))
            pair=configure_pair(local,remote,a,b,role,peer);attempt=uuid.uuid4().hex
            try:
                print('Installing the integrated stack on both servers...',flush=True)
                local.call('install',dict(attempt=attempt));remote.call('install',dict(attempt=attempt))
                if not local.call('probe',{})['healthy'] or not remote.call('probe',{})['healthy']:raise ValueError('Bidirectional site connectivity was not confirmed; rolling back the new installation.')
                print("Installing GRE, VXLAN and IPIP with this pair's generated configs...",flush=True)
                local.call('overlays',dict(attempt=attempt));remote.call('overlays',dict(attempt=attempt))
                if not local.call('probe',dict(overlays=True))['healthy'] or not remote.call('probe',dict(overlays=True))['healthy']:raise ValueError('Overlay connectivity test failed.')
            except BaseException:
                for name,endpoint in [('peer',remote),('local server',local)]:
                    try:endpoint.call('rollback',dict(attempt=attempt))
                    except (ValueError,OSError,subprocess.SubprocessError):print('Automatic rollback on '+name+' was not confirmed; check the private log and installation status.',file=sys.stderr)
                raise
            print('Both servers installed and connectivity verified. Keys remain private; no manual JSON editing required.',flush=True)
            return dict(success=True,pair_id=pair,role=role,overlays=['gre','vxlan','ipip'])

def main():
    p=argparse.ArgumentParser();p.add_argument('--role',choices=['listener','initiator'],required=True);p.add_argument('--peer',required=True);a=p.parse_args()
    try:install_pair(a.role,a.peer)
    except (ValueError,OSError,subprocess.SubprocessError) as exc:print('Easy installation failed: '+str(exc),file=sys.stderr);raise SystemExit(1)
if __name__=='__main__':main()
