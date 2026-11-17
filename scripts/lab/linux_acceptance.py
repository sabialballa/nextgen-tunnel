#!/usr/bin/env python3
"""Destructive acceptance tests restricted to an explicitly marked disposable VM.

Run as root only in the project-owned lab, never on a production server.
The marker is created manually by the VM provisioning step, not by this script.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

ROOT=Path(__file__).resolve().parents[2]
BINARY=ROOT/"bin/nextgen-tunnel"
INSTALL=ROOT/"scripts/host_install.py"
REPORT={"schema_version":1,"scope":"disposable Debian VM, real systemd and files", "checks":[]}

def command(name,args,expect=0,timeout=90):
    start=time.monotonic();p=subprocess.run([str(v) for v in args],capture_output=True,text=True,timeout=timeout)
    REPORT["checks"].append(dict(name=name,command=[str(v) for v in args],returncode=p.returncode,stdout=p.stdout,stderr=p.stderr,elapsed_seconds=time.monotonic()-start,expected_returncode=expect))
    print(name,p.returncode,flush=True)
    if expect is not None and p.returncode!=expect:raise RuntimeError(name+" failed: "+p.stderr[-1000:])
    return p

def require(name,value):
    REPORT["checks"].append(dict(name=name,assertion=bool(value)))
    if not value:raise RuntimeError(name)

def network_state():
    return {"routes":subprocess.check_output(["ip","-j","route","show"],text=True),"nftables":subprocess.check_output(["nft","list","ruleset"],text=True),"forwarding":Path('/proc/sys/net/ipv4/ip_forward').read_text()}

def exchange(address,network):
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM if network=="tcp" else socket.SOCK_DGRAM) as s:
        s.settimeout(4);s.connect(address);payload=os.urandom(160);s.sendall(payload);reply=bytearray()
        while len(reply)<len(payload):
            data=s.recv(65535)
            if not data:raise RuntimeError("early EOF")
            reply.extend(data)
        if bytes(reply)!=payload:raise RuntimeError("payload corruption")

def setup_echo():
    script=Path('/var/lib/nextgen-lab/echo.py');script.parent.mkdir(mode=0o700,exist_ok=True)
    script.write_text('''import socket,threading
def tcp():
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("127.0.0.1",19801));s.listen()
 def one(c):
  with c:
   while True:
    b=c.recv(65535)
    if not b:return
    c.sendall(b)
 while True:
  c,_=s.accept();threading.Thread(target=one,args=(c,),daemon=True).start()
def udp():
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("127.0.0.1",19802))
 while True:
  b,a=s.recvfrom(65535);s.sendto(b,a)
threading.Thread(target=tcp,daemon=True).start();udp()
''')
    Path('/etc/systemd/system/nextgen-lab-echo.service').write_text('[Unit]\nDescription=Disposable lab echo backend\n[Service]\nExecStart=/usr/bin/python3 /var/lib/nextgen-lab/echo.py\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n')
    command('echo_daemon_reload',['systemctl','daemon-reload'])
    command('echo_enable',['systemctl','enable','--now','nextgen-lab-echo'])

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--allow-disposable-host',action='store_true',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if sys.platform!='linux' or os.geteuid()!=0 or not Path('/etc/nextgen-lab-owned').exists():raise SystemExit('explicitly marked disposable root Linux VM required')
    REPORT['started_at']=time.time();REPORT['kernel']=os.uname().release;REPORT['os_release']=Path('/etc/os-release').read_text();REPORT['binary_sha256']=hashlib.sha256(BINARY.read_bytes()).hexdigest();REPORT['boot_id']=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    work=Path('/var/lib/nextgen-lab');work.mkdir(mode=0o700,exist_ok=True)
    try:
        setup_echo();baseline=network_state()
        pki=work/'pki'
        if not pki.exists():command('pki',[BINARY,'pki','-dir',pki])
        common=dict(max_sessions=32,idle_seconds=15,probe_seconds=1)
        server=dict(common,role='server',listen='127.0.0.1:18443',tls=dict(ca=str(pki/'ca.crt'),cert=str(pki/'server.crt'),key=str(pki/'server.key'),client_name='entry'),services={'tcp-echo':dict(protocol='tcp',target='127.0.0.1:19801'),'udp-echo':dict(protocol='udp',target='127.0.0.1:19802')})
        cfg=work/'server.json';cfg.write_text(json.dumps(server));digest=hashlib.sha256(BINARY.read_bytes()).hexdigest()
        def install(action,config=cfg,expect=0):return command(action,[sys.executable,INSTALL,action,'--binary',BINARY,'--sha256',digest,'--config',config,'--apply'],expect)
        install('install');pid=command('initial_pid',['systemctl','show','nextgen-tunnel','-p','MainPID','--value']).stdout.strip()
        install('install');require('idempotent_preserves_pid',pid==command('unchanged_pid',['systemctl','show','nextgen-tunnel','-p','MainPID','--value']).stdout.strip())
        client=dict(common,role='client',tls=dict(ca=str(pki/'ca.crt'),cert=str(pki/'client.crt'),key=str(pki/'client.key'),server_name='tunnel.internal'),endpoints=[dict(name='quic',protocol='quic',address='127.0.0.1:18443'),dict(name='tls',protocol='tls',address='127.0.0.1:18443')],forwards=[dict(service='tcp-echo',protocol='tcp',listen='127.0.0.1:19811'),dict(service='udp-echo',protocol='udp',listen='127.0.0.1:19812')],status_file=str(work/'client-status.json'))
        client_cfg=work/'client.json';client_cfg.write_text(json.dumps(client));command('authenticated_probe',[BINARY,'probe','-config',client_cfg])
        (work/'client-status.json').unlink(missing_ok=True)
        with (work/'client.log').open('wb') as log:
            proc=subprocess.Popen([str(BINARY),'run','-config',str(client_cfg)],stdout=log,stderr=log)
            try:
                for _ in range(30):
                    time.sleep(.25)
                    status=work/'client-status.json'
                    if status.exists() and json.loads(status.read_text()).get('selected'):break
                exchange(('127.0.0.1',19811),'tcp');exchange(('127.0.0.1',19812),'udp');require('installed_tcp_udp',True)
                bad=work/'conflicting.json';bad_server=dict(server,listen='127.0.0.1:19801');bad.write_text(json.dumps(bad_server));result=install('update',bad,expect=None);require('failed_update_rejected',result.returncode!=0)
                command('rollback_service_active',['systemctl','is-active','--quiet','nextgen-tunnel']);command('rollback_probe',[BINARY,'probe','-config',client_cfg])
                # Simulate abrupt installer death after a durable snapshot and a real
                # partial config write. No mocked filesystem or systemctl operations.
                crash="import os; from scripts import host_install as h; h.snapshot(h.FILES,{'lab_crash':True}); h.atomic(h.FILES[1],b'{}'); os._exit(73)"
                command('crashed_partial_update',[sys.executable,'-c',crash],expect=73)
                command('recover',[sys.executable,INSTALL,'recover','--apply']);command('recover_idempotent',[sys.executable,INSTALL,'recover','--apply']);command('recovered_probe',[BINARY,'probe','-config',client_cfg])
                command('service_restart',['systemctl','restart','nextgen-tunnel']);command('restart_probe',[BINARY,'probe','-config',client_cfg])
                props=command('hardening_properties',['systemctl','show','nextgen-tunnel','-p','User','-p','NoNewPrivileges','-p','ProtectSystem','-p','PrivateDevices','-p','CapabilityBoundingSet']).stdout
                require('hardening_enforced','User=nextgen-tunnel' in props and 'NoNewPrivileges=yes' in props and 'ProtectSystem=strict' in props)
                command('systemd_unit_verify',['systemd-analyze','verify','/etc/systemd/system/nextgen-tunnel.service'])
                command('systemd_security',['systemd-analyze','security','nextgen-tunnel.service','--no-pager'],expect=None)
                command('private_installer_state',['runuser','-u','nextgen-tunnel','--','test','-r','/var/lib/nextgen-tunnel-installer/ownership.json'],expect=1)
                require('routes_firewall_forwarding_unchanged',baseline==network_state())
            finally:proc.terminate();proc.wait(timeout=10)
        command('uninstall',[sys.executable,INSTALL,'uninstall','--apply']);command('uninstall_idempotent',[sys.executable,INSTALL,'uninstall','--apply'])
        require('owned_files_removed',all(not Path(v).exists() for v in ('/usr/local/bin/nextgen-tunnel','/etc/nextgen-tunnel/config.json','/etc/systemd/system/nextgen-tunnel.service')))
        install('install');command('enabled_for_reboot',['systemctl','is-enabled','--quiet','nextgen-tunnel']);require('final_network_unchanged',baseline==network_state())
        REPORT['success']=True
    except BaseException as e:
        REPORT['success']=False;REPORT['error']=str(e)
        REPORT['journal']=subprocess.run(['journalctl','-u','nextgen-tunnel','-n','30','--no-pager'],capture_output=True,text=True).stdout
        raise
    finally:
        REPORT['finished_at']=time.time();a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(REPORT,indent=2))

if __name__=='__main__':main()
