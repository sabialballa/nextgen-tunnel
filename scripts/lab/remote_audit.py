#!/usr/bin/env python3
"""Read-only SSH audit with explicit host-key pinning and nonpersistent passwords.

Install the optional Paramiko client into .private/sshclient. Passwords are read
from the console, never from arguments, config files, archives or environment.
The fingerprint command performs no authentication and only captures public keys.
"""
import argparse
import base64
import getpass
import hashlib
import json
from pathlib import Path
import socket
import struct
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'.private/sshclient'))
import paramiko
STATE=ROOT/'.private/remote-lab'

def fingerprint(key):return 'SHA256:'+base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip('=')

def open_socket(host,port,interface=None,bind_ip=None,timeout=25):
    if not interface:return socket.create_connection((host,port),timeout=timeout)
    sock=socket.socket();sock.settimeout(timeout)
    try:
        # Windows requires the interface index in network byte order.
        sock.setsockopt(socket.IPPROTO_IP,31,struct.pack('!I',interface))
        sock.bind((bind_ip,0));sock.connect((host,port));return sock
    except BaseException:
        sock.close();raise

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('fingerprint','approve','audit','session'));p.add_argument('--host',required=True);p.add_argument('--expected');p.add_argument('--port',type=int,default=22);p.add_argument('--output',type=Path)
    p.add_argument('--direct-interface',type=int,help='Windows IPv4 egress interface index for this SSH connection only')
    p.add_argument('--bind-ip',help='local IPv4 address on the selected direct interface')
    a=p.parse_args()
    socket.inet_aton(a.host)
    if not 1<=a.port<=65535:p.error('invalid SSH port')
    if a.direct_interface is not None:
        if sys.platform!='win32' or not a.bind_ip or not 1<=a.direct_interface<=0xffffffff:p.error('direct-interface requires Windows, valid index and bind-ip')
        socket.inet_aton(a.bind_ip)
    elif a.bind_ip:p.error('bind-ip requires direct-interface')
    STATE.mkdir(parents=True,exist_ok=True);pending=STATE/(a.host+'.public-host-key.json');known=STATE/'known_hosts'
    if a.action=='fingerprint':
        sock=open_socket(a.host,a.port,a.direct_interface,a.bind_ip,10);transport=paramiko.Transport(sock)
        try:
            transport.get_security_options().key_types=('rsa-sha2-512','rsa-sha2-256')
            transport.start_client(timeout=15);key=transport.get_remote_server_key();data=dict(host=a.host,port=a.port,key_type=key.get_name(),key=key.get_base64(),fingerprint=fingerprint(key),authenticated=False)
            pending.write_text(json.dumps(data,indent=2));print(json.dumps({k:v for k,v in data.items() if k!='key'}))
        finally:transport.close()
        return
    data=json.loads(pending.read_text())
    if a.action=='approve':
        if a.expected!=data['fingerprint']:p.error('expected out-of-band fingerprint must match captured key')
        host=a.host if a.port==22 else f'[{a.host}]:{a.port}'
        keyfile=paramiko.HostKeys(str(known)) if known.exists() else paramiko.HostKeys()
        key=paramiko.RSAKey(data=base64.b64decode(data['key']));keyfile.add(host,data['key_type'],key);keyfile.save(str(known));print('Pinned the explicitly approved host key');return
    if not known.exists():p.error('approve the verified host key first')
    client=paramiko.SSHClient();client.load_host_keys(str(known));client.set_missing_host_key_policy(paramiko.RejectPolicy())
    password=getpass.getpass('SSH password (not saved): ')
    try:
        for attempt in range(3):
            try:
                direct=None
                if a.direct_interface:
                    direct=open_socket(a.host,a.port,a.direct_interface,a.bind_ip)
                client.connect(a.host,port=a.port,username='root',password=password,sock=direct,look_for_keys=False,allow_agent=False,timeout=25,banner_timeout=25,auth_timeout=25,disabled_algorithms={'keys':['ssh-ed25519','ecdsa-sha2-nistp256','ecdsa-sha2-nistp384','ecdsa-sha2-nistp521','ssh-rsa']});break
            except (TimeoutError,socket.timeout):
                if direct is not None:direct.close()
                if attempt==2:raise
                time.sleep(2)
        password=None
        client.get_transport().set_keepalive(20)
        if a.action=='session':
            print('Authenticated. JSON operations: exec, put, get, close.',flush=True)
            sftp=client.open_sftp()
            for line in sys.stdin:
                try:
                    request=json.loads(line);operation=request['op']
                    if operation=='close':break
                    if operation=='exec':
                        _,out,err=client.exec_command(request['command'],timeout=min(900,int(request.get('timeout',90))));result={}
                        result['stdout']=out.read(4<<20).decode(errors='replace');result['stderr']=err.read(1<<20).decode(errors='replace');result['returncode']=out.channel.recv_exit_status()
                    elif operation=='put':sftp.put(request['local'],request['remote']);sftp.chmod(request['remote'],int(request.get('mode',384)));result={'uploaded':True}
                    elif operation=='get':sftp.get(request['remote'],request['local']);result={'downloaded':True}
                    else:raise ValueError('invalid operation')
                    print(json.dumps(result),flush=True)
                except Exception as exc:print(json.dumps({'error':str(exc)}),flush=True)
            sftp.close();return
        checks={
          'os':'cat /etc/os-release; uname -sr; uptime',
          'listeners':'ss -H -lntup',
          'services':'systemctl list-units --type=service --state=running --no-pager',
          'routes':'ip -j route show; ip -j -6 route show',
          'interfaces':'ip -j address show',
          'firewall':'nft list ruleset 2>/dev/null; iptables-save 2>/dev/null',
          'ssh':'systemctl is-active ssh sshd; ss -H -tn state established sport = :22',
          'resources':'free -b; df -h /; command -v python3; command -v iperf3; cat /proc/net/dev'
        }
        report=dict(timestamp=time.time(),host=a.host,host_fingerprint=data['fingerprint'],read_only=True,checks={})
        for name,command in checks.items():
            _,out,err=client.exec_command(command,timeout=30);stdout=out.read(1<<20).decode(errors='replace');stderr=err.read(1<<16).decode(errors='replace');report['checks'][name]=dict(returncode=out.channel.recv_exit_status(),stdout=stdout,stderr=stderr)
        path=a.output or STATE/(a.host+'-audit.json');path.write_text(json.dumps(report,indent=2));print(json.dumps(dict(output=str(path),read_only=True,checks=len(checks))))
    finally:password=None;client.close()
if __name__=='__main__':main()

