#!/usr/bin/env python3
"""Two-host orchestration over existing, strictly verified SSH key access."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import sys
import tarfile
import time
from model import validate, role_plan

ROOT = Path(__file__).resolve().parent
AGENT = "/usr/local/libexec/gaming-tunnel/agent.py"

def ssh(config, role, command, data=b"", timeout=90):
    e = config[role]
    args = ["ssh","-o","BatchMode=yes","-o","StrictHostKeyChecking=yes",
            "-o","ConnectTimeout=10","-o","ServerAliveInterval=10",
            "-o","ServerAliveCountMax=3","-p",str(e.get("ssh_port",22))]
    if e.get("identity_file"):
        args += ["-i",e["identity_file"]]
    args += ["root@"+e.get("ssh_host",e["public_ip"]),command]
    p = subprocess.run(args,input=data,capture_output=True,timeout=timeout)
    if p.returncode:
        raise RuntimeError(f"{role}: SSH/remote command failed: "+p.stderr.decode(errors="replace")[-1000:])
    return p.stdout

def invoke(config,role,action,payload=None,tag=None,agent=AGENT,timeout=90):
    args = ["python3",agent,action]+([tag] if tag else [])
    raw = ssh(config,role,shlex.join(args),
              json.dumps(payload).encode() if payload is not None else b"",timeout)
    return json.loads(raw)

def package(binary=None):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream,mode="w:gz") as t:
        files = [ROOT/"agent.py",ROOT/"model.py",ROOT/"runtime"/"soak.py"]
        files += sorted((ROOT/"runtime").glob("*.in"))
        files += [ROOT/"runtime"/"receive-buffer.py"]
        for path in dict.fromkeys(files):
            t.add(path,arcname=str(path.relative_to(ROOT)),recursive=False)
        if binary:
            t.add(binary,arcname="udp2raw",recursive=False)
    return stream.getvalue()

def upload(config,role,binary=None):
    path = "/root/.cache/gaming-tunnel/"+secrets.token_hex(8)
    ssh(config,role,"umask 077; mkdir -p "+shlex.quote(path))
    ssh(config,role,"tar -xzf - -C "+shlex.quote(path),package(binary))
    return path+"/agent.py"

def local_secret(config):
    digest = hashlib.sha256(json.dumps(config,sort_keys=True).encode()).hexdigest()[:16]
    directory = ROOT/".private"/digest
    directory.mkdir(parents=True,mode=0o700,exist_ok=True)
    os.chmod(directory,0o700)
    path = directory/"carrier.key"
    if not path.exists():
        fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"w") as f:
            f.write(secrets.token_hex(32))
    return directory,path.read_text().strip()

def deploy(args,config):
    binary = Path(args.binary)
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    if digest != args.sha256.lower():
        raise ValueError("local carrier checksum mismatch")
    prepared = {}
    for role in ("exit","entry"):
        staged = upload(config,role,binary)
        prepared[role] = invoke(config,role,"prepare",dict(configuration=config,
                    install_deps=args.install_deps,raw_sha256=digest),agent=staged,timeout=300)
        print(role+": prepared; private WireGuard key remains on that server",flush=True)
    ports = prepared["exit"]["audit"]["vpn_ports"]
    if not any(ports.values()):
        raise RuntimeError("no supported VPN listener found on exit")
    print("Detected backend transports:",json.dumps(ports),flush=True)
    keys = {r:v["public_key"] for r,v in prepared.items()}
    directory,secret = local_secret(config)
    tag = secrets.token_hex(8)
    transactions = {}
    try:
        for role in ("exit","entry"):
            p = role_plan(config,role,keys,secret,ports)
            result = invoke(config,role,"apply",dict(plan=p,transaction=tag))
            transactions[role] = result["transaction"]
            print(role+": "+("unchanged" if result.get("noop") else "tunnel configured"),flush=True)
        if len(set(transactions.values())) != 1:
            raise RuntimeError("pair has different installation transactions; use a maintenance migration")
        effective_tag = transactions["entry"]
        # Do not expose forwarding until data-plane connectivity is verified.
        for role in ("exit","entry"):
            success = False
            for _ in range(6):
                try:
                    invoke(config,role,"health")
                    success = True
                    break
                except RuntimeError:
                    time.sleep(2)
            if not success:
                raise RuntimeError(role+": data-plane health failed")
        for role in ("exit","entry"):
            invoke(config,role,"activate")
        for role in ("exit","entry"):
            invoke(config,role,"health")
        for role in ("exit","entry"):
            invoke(config,role,"commit",tag=effective_tag)
        (directory/"last-transaction.txt").write_text(effective_tag)
        print("Deployment verified; rollback transaction:",effective_tag)
    except BaseException:
        for role in ("entry","exit"):
            try:
                invoke(config,role,"rollback",tag=tag)
            except Exception:
                print(role+": immediate rollback failed; 15-minute rollback timer remains the fallback",file=sys.stderr)
        raise

def soak(args,config):
    tag = secrets.token_hex(8)
    payload = dict(tag=tag,seconds=args.seconds,tcp_mbit=args.tcp_mbit,udp_mbit=args.udp_mbit)
    started = []
    try:
        for role in ("exit","entry"):
            invoke(config,role,"bench-servers",payload)
            started.append(role)
        for role in ("exit","entry"):
            invoke(config,role,"bench-start",payload)
        deadline = time.monotonic()+args.seconds+90
        while time.monotonic()<deadline:
            time.sleep(30)
            snapshots = {role:invoke(config,role,"bench-status",tag=tag) for role in ("entry","exit")}
            print(json.dumps(snapshots),flush=True)
            if any(v.get("stop_reason") for v in snapshots.values()):
                raise RuntimeError("benchmark safety threshold reached; test traffic is being stopped")
            if all(v.get("finished") for v in snapshots.values()):
                if not all(v.get("data_duration_completed") for v in snapshots.values()):
                    raise RuntimeError("soak ended before the requested duration")
                print("Soak finished. Receiver logs and JSON remain under /var/lib/gaming-tunnel/bench/"+tag)
                return
        raise RuntimeError("benchmark deadline reached")
    finally:
        for role in started:
            try:
                invoke(config,role,"bench-stop",tag=tag)
            except Exception:
                print(role+": test cleanup failed; runtime deadlines remain armed",file=sys.stderr)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("action",choices=("audit","deploy","status","rollback","repair-l2tp","soak"))
    p.add_argument("config",type=Path)
    p.add_argument("--binary")
    p.add_argument("--sha256")
    p.add_argument("--install-deps",action="store_true")
    p.add_argument("--transaction")
    p.add_argument("--seconds",type=int,default=900)
    p.add_argument("--tcp-mbit",type=int,default=20)
    p.add_argument("--udp-mbit",type=int,default=1)
    a = p.parse_args()
    config = json.loads(a.config.read_text())
    validate(config)
    if a.action=="deploy":
        if not a.binary or not a.sha256:
            p.error("deploy requires --binary and --sha256 from a trusted source")
        deploy(a,config)
    elif a.action=="audit":
        for role in ("entry","exit"):
            print(role,json.dumps(invoke(config,role,"audit",agent=upload(config,role))))
    elif a.action=="soak":
        if not 30<=a.seconds<=1800 or not 1<=a.tcp_mbit<=40 or not 1<=a.udp_mbit<=2:
            p.error("protected soak supports 30..1800s, TCP1..40Mbps and UDP1..2Mbps per direction")
        soak(a,config)
    elif a.action=="repair-l2tp":
        print(json.dumps(invoke(config,"exit","repair-l2tp")))
    else:
        if a.action=="rollback" and (not a.transaction or not __import__("re").fullmatch("[a-f0-9]{16}",a.transaction)):
            p.error("rollback requires --transaction from a successful deploy")
        for role in ("entry","exit"):
            print(role,json.dumps(invoke(config,role,"health" if a.action=="status" else "rollback",tag=a.transaction)))

if __name__=="__main__":
    try:
        main()
    except (ValueError,KeyError,RuntimeError,subprocess.TimeoutExpired) as e:
        print(f"ERROR: {e}",file=sys.stderr)
        sys.exit(1)
