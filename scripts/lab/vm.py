#!/usr/bin/env python3
"""Project-local QEMU/cloud-init lab. No host routes, firewall or Windows features.

Secrets, VM disks, SSH identities and serial logs stay in .private/linux-lab.
SSH host keys are generated locally and pinned before first connection.
"""
import argparse
import functools
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[2]
LAB=ROOT/".private/linux-lab"

def hidden():
    return {"creationflags":subprocess.CREATE_NO_WINDOW} if os.name=="nt" else {"start_new_session":True}

def start(name,ssh_port,seed_port,accelerator):
    directory=LAB/name
    directory.mkdir(parents=True,exist_ok=True)
    if (directory/"running.json").exists():raise ValueError("existing VM state; inspect before restarting")
    seed=directory/"seed";seed.mkdir(exist_ok=True)
    for key in ("identity","host"):
        if not (directory/key).exists():
            subprocess.run(["ssh-keygen","-q","-t","ed25519","-N","","-f",str(directory/key)],check=True)
    pub=(directory/"identity.pub").read_text().strip()
    host_pub=(directory/"host.pub").read_text().split()
    host_private=(directory/"host").read_text().splitlines()
    user_data=["#cloud-config","users:","  - name: lab","    sudo: ALL=(ALL) NOPASSWD:ALL","    shell: /bin/bash","    ssh_authorized_keys:","      - "+pub,"ssh_pwauth: false","disable_root: true","ssh_keys:","  ed25519_public: "+" ".join(host_pub[:2]),"  ed25519_private: |"]
    user_data += ["    "+line for line in host_private]
    user_data += ["package_update: false"]
    (seed/"user-data").write_text("\n".join(user_data)+"\n")
    (seed/"meta-data").write_text("instance-id: nextgen-"+name+"\nlocal-hostname: nextgen-"+name+"\n")
    (seed/"vendor-data").write_text("#cloud-config\n")
    known=directory/"known_hosts"
    known.write_text(f"[127.0.0.1]:{ssh_port} "+" ".join(host_pub[:2])+"\n")
    qemu=LAB/"qemu/qemu-system-x86_64.exe"
    disk=directory/"disk.qcow2"
    if not disk.exists():
        subprocess.run([str(LAB/"qemu/qemu-img.exe"),"create","-f","qcow2","-F","qcow2","-b",str(LAB/"downloads/debian.qcow2"),str(disk),"14G"],check=True,capture_output=True)
    logs=[]
    for name_log in ("http.stdout","http.stderr","qemu.stdout","qemu.stderr"):
        logs.append(open(directory/name_log,"ab"))
    http=subprocess.Popen([sys.executable,str(Path(__file__).resolve()),"serve","--directory",str(seed),"--port",str(seed_port)],stdout=logs[0],stderr=logs[1],**hidden())
    args=[str(qemu),"-name","nextgen-lab-"+name,"-machine","q35","-accel","whpx","-accel","tcg,thread=multi","-smp","2","-m","3072","-drive",f"file={disk},if=virtio,format=qcow2","-netdev",f"user,id=n0,hostfwd=tcp:127.0.0.1:{ssh_port}-:22","-device","virtio-net-pci,netdev=n0","-display","none","-monitor","none","-serial","file:"+str(directory/"serial.log"),"-smbios",f"type=1,serial=ds=nocloud-net;s=http://10.0.2.2:{seed_port}/"]
    if accelerator=='tcg':args[args.index('-accel'):args.index('-smp')]=['-accel','tcg,thread=multi']
    try:
        vm=subprocess.Popen(args,stdout=logs[2],stderr=logs[3],**hidden())
        time.sleep(1)
        if vm.poll() is not None:raise RuntimeError("QEMU exited; inspect private qemu.stderr")
        (directory/"running.json").write_text(json.dumps(dict(vm_pid=vm.pid,http_pid=http.pid,ssh_port=ssh_port,seed_port=seed_port,started=time.time())))
    except BaseException:
        http.terminate();http.wait();raise
    finally:
        for f in logs:f.close()
    print(json.dumps({"name":name,"pid":vm.pid,"ssh_port":ssh_port,"disk":str(disk),"host_network_changes":False}))

def ssh_args(name):
    directory=LAB/name;s=json.loads((directory/"running.json").read_text())
    return ["ssh","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes","-o","IdentitiesOnly=yes","-o","ConnectTimeout=5","-o","UserKnownHostsFile="+str(directory/"known_hosts"),"-i",str(directory/"identity"),"-p",str(s["ssh_port"]),"lab@127.0.0.1"]

def main():
    p=argparse.ArgumentParser(description=__doc__);sp=p.add_subparsers(dest="action",required=True)
    s=sp.add_parser("start");s.add_argument("--name",default="debian12");s.add_argument("--ssh-port",type=int,default=22287);s.add_argument("--seed-port",type=int,default=18083);s.add_argument('--accelerator',choices=('whpx','tcg'),default='whpx')
    s=sp.add_parser("serve");s.add_argument("--directory",required=True);s.add_argument("--port",type=int,required=True)
    s=sp.add_parser("ssh");s.add_argument("--name",default="debian12");s.add_argument("command",nargs="?",default="uname -a; systemctl is-system-running")
    for action in ("push","pull"):
        s=sp.add_parser(action);s.add_argument("--name",default="debian12");s.add_argument("source");s.add_argument("destination")
    a=p.parse_args()
    if a.action=="start":
        if not a.name.replace("-","").isalnum():p.error("invalid name")
        start(a.name,a.ssh_port,a.seed_port,a.accelerator)
    elif a.action=="serve":
        handler=functools.partial(http.server.SimpleHTTPRequestHandler,directory=a.directory)
        http.server.ThreadingHTTPServer(("127.0.0.1",a.port),handler).serve_forever()
    elif a.action in ("push","pull"):
        args=ssh_args(a.name);options=args[1:-1];options[options.index("-p")]="-P"
        source=str(Path(a.source).resolve()) if a.action=="push" else args[-1]+":"+a.source
        destination=args[-1]+":"+a.destination if a.action=="push" else str(Path(a.destination).resolve())
        raise SystemExit(subprocess.run(["scp",*options,source,destination]).returncode)
    else:raise SystemExit(subprocess.run(ssh_args(a.name)+[a.command]).returncode)
if __name__=="__main__":main()
