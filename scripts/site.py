#!/usr/bin/env python3
"""Owned WireGuard L3 site namespace over a loopback UDP carrier.

The kernel UDP socket is created before moving the interface into the isolated
namespace. Its only configured peer endpoint is loopback; host routes stay intact.
An external Hysteria2/REALITY UDP forwarding inbound supplies the carrier.
"""
import argparse
import base64
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile

STATE=Path('/var/lib/nextgen-sites')
WIREGUARD_DIR=Path('/etc/wireguard')
def safe_error(text):
    text=re.sub(r'(?im)((?:PrivateKey|PresharedKey)\s*=)\s*[^\r\n]*',r'\1 [redacted]',text)
    return re.sub(r'[A-Za-z0-9+/]{43}=', '[redacted-key]', text).strip()[-2000:]

def run(args,data=None):
    result=subprocess.run(args,input=data,capture_output=True,text=True)
    if result.returncode:
        detail=safe_error(result.stderr or 'No error details returned.')
        raise ValueError(f'{Path(args[0]).name} {args[1] if len(args)>1 else ""} failed (exit {result.returncode}): {detail}')
    return result.stdout
def key(value):
    if len(base64.b64decode(value,validate=True))!=32:raise ValueError('invalid WireGuard key')
    return value

def wireguard_directory():
    """Use the standard path permitted by distribution WireGuard profiles."""
    directory=WIREGUARD_DIR
    if any(p.is_symlink() for p in (directory,*directory.parents)):raise ValueError('symlink in WireGuard configuration path')
    directory.mkdir(mode=0o700,exist_ok=True)
    st=directory.stat()
    if st.st_uid!=0 or st.st_mode&0o022:raise ValueError('WireGuard configuration directory must be root-owned and not writable by other users')
    return directory

def apply_wireguard_config(interface,text):
    # Ubuntu's wg AppArmor profile permits /etc/wireguard, not arbitrary state
    # paths. Do not disable confinement, broaden permissions, or pass keys in argv.
    directory=wireguard_directory()
    fd,name=tempfile.mkstemp(prefix='nextgen-site-',suffix='.conf',dir=directory)
    config=Path(name)
    try:
        with os.fdopen(fd,'w') as handle:
            if hasattr(os,'fchmod'):os.fchmod(handle.fileno(),0o600)
            else:config.chmod(0o600)
            handle.write(text)
        run(['wg','setconf',interface,str(config)])
    finally:
        config.unlink(missing_ok=True)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('keygen','create','status','remove'));p.add_argument('--config',type=Path);p.add_argument('--directory',type=Path);p.add_argument('--name');p.add_argument('--apply',action='store_true');p.add_argument('--recover-boot',action='store_true',help='recreate owned state after a different boot, never an unknown namespace');a=p.parse_args()
    if sys.platform!='linux' or not shutil.which('wg') or not shutil.which('ip'):p.error('Linux, iproute2 and wireguard-tools are required')
    if a.action=='keygen':
        if not a.directory:p.error('--directory required')
        a.directory.mkdir(mode=0o700,parents=True,exist_ok=False)
        private=run(['wg','genkey']).strip();(a.directory/'private.key').write_text(private+'\n');(a.directory/'private.key').chmod(0o600)
        (a.directory/'public.key').write_text(run(['wg','pubkey'],private+'\n'));print('generated private key locally; public.key can be exchanged');return
    cfg=json.loads(a.config.read_text()) if a.config else {};name=a.name or cfg.get('name','')
    if not re.fullmatch(r'ngt-site-[a-z0-9_-]{1,18}',name):p.error('dedicated ngt-site- name required')
    path=STATE/name;marker=path/'ownership.json';ns=Path('/run/netns')/name
    if a.action=='status':print(run(['ip','netns','exec',name,'wg','show']));return
    if not a.apply:print(json.dumps(dict(action=a.action,namespace=name,host_routes_changed=False)));return
    if os.geteuid()!=0:p.error('--apply requires root')
    if any(v.is_symlink() for v in (STATE,path,marker)):p.error('symlink in ownership state')
    STATE.mkdir(mode=0o700,exist_ok=True)
    if STATE.stat().st_uid!=0 or STATE.stat().st_mode&0o022:p.error('unsafe ownership state')
    boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    if a.action=='remove':
        if not marker.exists():
            if ns.exists():p.error('unmanaged namespace')
            print('absent');return
        owned=json.loads(marker.read_text())
        if ns.exists():
            if owned.get('inode')!=ns.stat().st_ino:p.error('namespace ownership mismatch')
            if run(['ip','netns','pids',name]).strip():p.error('stop namespace applications first')
            if any(v['ifname'].startswith('ngo-') for v in json.loads(run(['ip','-n',name,'-j','link','show']))):p.error('stop/remove GRE or VXLAN overlays before removing their site')
            run(['ip','-n',name,'link','delete','wg0']);run(['ip','netns','del',name])
        (path/'wg.conf').unlink(missing_ok=True);marker.unlink();path.rmdir();print('removed owned site');return
    if ns.exists():
        if not marker.exists() or json.loads(marker.read_text()).get('inode')!=ns.stat().st_ino:p.error('unmanaged namespace')
        if json.loads(marker.read_text()).get('config')!=cfg:p.error('site config changed; remove/recreate explicitly')
        print('unchanged');return
    if marker.exists() and a.recover_boot:
        owned=json.loads(marker.read_text())
        if owned.get('boot_id') and owned['boot_id']!=boot_id and owned.get('config')==cfg:
            (path/'wg.conf').unlink(missing_ok=True);marker.unlink();path.rmdir()
    if marker.exists():p.error('unfinished site operation; inspect ownership before recovery')
    private=key(Path(cfg['private_key_file']).read_text().strip());peer=key(cfg['peer_public_key']);psk=key(Path(cfg['preshared_key_file']).read_text().strip()) if cfg.get('preshared_key_file') else None
    addresses=[str(ipaddress.ip_interface(v)) for v in cfg['addresses']];routes=[str(ipaddress.ip_network(v,strict=True)) for v in cfg['remote_routes']]
    if not addresses or not routes:p.error('explicit addresses and routes required')
    port=cfg['listen_port'];mtu=cfg.get('mtu',1360)
    if type(port)!=int or not 1024<=port<=65535 or type(mtu)!=int or not 1280<=mtu<=1420:p.error('invalid port or MTU')
    endpoint=cfg.get('endpoint')
    if endpoint:
        host,sep,number=endpoint.rpartition(':')
        if not sep or not ipaddress.ip_address(host).is_loopback or not 1024<=int(number)<=65535:p.error('site carrier endpoint must be loopback IPv4')
    keepalive=cfg.get('persistent_keepalive',25)
    if type(keepalive)!=int or not 0<=keepalive<=65535:p.error('invalid persistent keepalive')
    path.mkdir(mode=0o700);text=f'[Interface]\nPrivateKey = {private}\nListenPort = {port}\n[Peer]\nPublicKey = {peer}\nAllowedIPs = '+', '.join(routes)+f'\nPersistentKeepalive = {keepalive}\n'
    if psk:text+='PresharedKey = '+psk+'\n'
    if endpoint:text+='Endpoint = '+endpoint+'\n'
    config=path/'wg.conf' # Legacy cleanup only; private config is now ephemeral.
    temporary='ngw'+secrets.token_hex(4);created=False;in_ns=False;namespace_created=False
    try:
        run(['ip','netns','add',name]);namespace_created=True;inode=ns.stat().st_ino;marker.write_text(json.dumps(dict(inode=inode,config=cfg,boot_id=boot_id)));marker.chmod(0o600)
        run(['ip','link','add',temporary,'type','wireguard']);created=True;apply_wireguard_config(temporary,text)
        run(['ip','link','set',temporary,'netns',name]);in_ns=True;run(['ip','-n',name,'link','set',temporary,'name','wg0']);run(['ip','-n',name,'link','set','lo','up'])
        for address in addresses:run(['ip','-n',name,'address','add',address,'dev','wg0'])
        run(['ip','-n',name,'link','set','wg0','mtu',str(mtu),'up'])
        for route in routes:run(['ip','-6' if ':' in route else '-4','-n',name,'route','replace',route,'dev','wg0'])
    except BaseException:
        if created and not in_ns:subprocess.run(['ip','link','delete',temporary],capture_output=True)
        if namespace_created and ns.exists():subprocess.run(['ip','netns','del',name],capture_output=True)
        config.unlink(missing_ok=True);marker.unlink(missing_ok=True);path.rmdir();raise
    print('site namespace ready; peer handshake requires the loopback carrier')
if __name__=='__main__':
    try:main()
    except (ValueError,OSError,KeyError,subprocess.SubprocessError) as exc:
        print('site operation failed: '+safe_error(str(exc)),file=sys.stderr);raise SystemExit(1)
