#!/usr/bin/env python3
"""Root-side installer. Invoked by tunnelctl over authenticated SSH."""
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
from model import PORTS, role_plan, validate

ETC = Path("/etc/gaming-tunnel")
STATE = Path("/var/lib/gaming-tunnel")
LIB = Path("/usr/local/libexec/gaming-tunnel")
RAW = LIB / "udp2raw"
ROOT = Path(__file__).resolve().parent
UNITS = ["gaming-monitor.timer", "gaming-monitor.service", "gaming-forward.service",
         "wg-quick@{iface}.service", "gaming-raw.service", "gaming-address.service"]

def run(args, check=True, data=None):
    p = subprocess.run(args, input=data, text=True, capture_output=True)
    if check and p.returncode:
        raise RuntimeError(f"command failed: {args[0]} {args[1] if len(args)>1 else ''}")
    return p

def write(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".gaming-")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)

def state():
    p = STATE / "state.json"
    return json.loads(p.read_text()) if p.exists() else {}

def save_state(s):
    write(STATE / "state.json", json.dumps(s))

def template(name, replacements):
    value = (ROOT / "runtime" / name).read_text()
    for key, text in replacements.items():
        value = value.replace("@"+key+"@", str(text))
    if re.search(r"@[A-Z_]+@", value):
        raise ValueError("unresolved runtime template placeholder")
    return value

def checked_plan(p):
    if p.get("role") not in ("entry", "exit"):
        raise ValueError("invalid role")
    other = "exit" if p["role"] == "entry" else "entry"
    c = {"entry": {}, "exit": {}, "tunnel": p}
    c[p["role"]] = {"public_ip": p["public_ip"]}
    c[other] = {"public_ip": p["peer_public_ip"]}
    q = role_plan(c, p["role"], {"entry": p["peer_key"], "exit": p["peer_key"]},
                  p["carrier_key"], p["vpn_ports"])
    for key in ("link_local", "link_peer", "service_local", "service_peer"):
        if p[key] != q[key]:
            raise ValueError("derived network address mismatch")
    return q

def forward_script(p):
    iface = p["interface"]
    down = 'if [ "$#" -ge 1 ] && [ "$1" = down ]; then'
    if p["role"] == "entry":
        out = ["#!/bin/bash", "set -euo pipefail", down,
               f" iptables -w -t nat -D PREROUTING -i @WAN@ -d {p['public_ip']} -j GAME_DNAT 2>/dev/null || true",
               f" iptables -w -t nat -D POSTROUTING -o {iface} -j GAME_SNAT 2>/dev/null || true",
               " for c in GAME_DNAT GAME_SNAT; do iptables -w -t nat -F $c 2>/dev/null || true; iptables -w -t nat -X $c 2>/dev/null || true; done",
               " exit 0", "fi",
               "for c in GAME_DNAT GAME_SNAT; do iptables -w -t nat -N $c 2>/dev/null || true; iptables -w -t nat -F $c; done"]
        for proto in ("udp", "tcp"):
            ports = p["vpn_ports"].get(proto, [])
            if not ports:
                continue
            match = f"-p {proto} -m multiport --dports {','.join(map(str,ports))}"
            out += [f"iptables -w -t nat -A GAME_DNAT {match} -j DNAT --to-destination {p['service_peer']}",
                    f"iptables -w -t nat -A GAME_SNAT -d {p['service_peer']} {match} -j SNAT --to-source {p['service_local']}"]
        for chain, spec, target in (
            ("PREROUTING", f"-i @WAN@ -d {p['public_ip']}", "GAME_DNAT"),
            ("POSTROUTING", f"-o {iface}", "GAME_SNAT")):
            out += [f"iptables -w -t nat -C {chain} {spec} -j {target} 2>/dev/null || iptables -w -t nat -I {chain} 1 {spec} -j {target}"]
    else:
        subnet, mss = p["ppp_subnet"], p["l2tp_mss"]
        out = ["#!/bin/bash", "set -euo pipefail", down,
               f" iptables -w -D INPUT -i {iface} -p udp --dport 1701 -j GAME_L2TP 2>/dev/null || true",
               " iptables -w -F GAME_L2TP 2>/dev/null || true", " iptables -w -X GAME_L2TP 2>/dev/null || true",
               " iptables -w -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j GAME_L2TP_MSS 2>/dev/null || true",
               " iptables -w -t mangle -F GAME_L2TP_MSS 2>/dev/null || true",
               " iptables -w -t mangle -X GAME_L2TP_MSS 2>/dev/null || true", " exit 0", "fi",
               "iptables -w -N GAME_L2TP 2>/dev/null || true", "iptables -w -F GAME_L2TP",
               "iptables -w -A GAME_L2TP -m policy --dir in --pol ipsec -j ACCEPT",
               "iptables -w -A GAME_L2TP -j DROP",
               f"iptables -w -C INPUT -i {iface} -p udp --dport 1701 -j GAME_L2TP 2>/dev/null || iptables -w -I INPUT 1 -i {iface} -p udp --dport 1701 -j GAME_L2TP",
               "iptables -w -t mangle -N GAME_L2TP_MSS 2>/dev/null || true", "iptables -w -t mangle -F GAME_L2TP_MSS"]
        for spec in (f"-i ppp+ -s {subnet}", f"-o ppp+ -d {subnet}"):
            out += [f"iptables -w -t mangle -A GAME_L2TP_MSS {spec} -p tcp --tcp-flags SYN,RST SYN -m tcpmss --mss {mss+1}:65535 -j TCPMSS --set-mss {mss}"]
        out += ["iptables -w -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j GAME_L2TP_MSS 2>/dev/null || iptables -w -t mangle -I FORWARD 1 -p tcp --tcp-flags SYN,RST SYN -j GAME_L2TP_MSS"]
    return "\n".join(out)+"\n"

def unit(description, body):
    return f"[Unit]\nDescription={description}\nAfter=network-online.target\nWants=network-online.target\n{body}"

def render(p, private_key, wan="eth0"):
    p = checked_plan(p)
    if not re.fullmatch(r"[A-Za-z0-9+/]{43}=", private_key):
        raise ValueError("invalid local WireGuard private key")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", wan):
        raise ValueError("invalid uplink interface")
    values = dict(IFACE=p["interface"], MTU=p["mtu"], RATE=p["rate_mbit"],
                  RTT=p["rtt_ms"], OVERHEAD=p["overhead"],
                  SERVICE_LOCAL=p["service_local"], SERVICE_PEER=p["service_peer"])
    outputs = {
        "/usr/local/sbin/gaming-address": template("address.sh.in", values),
        "/usr/local/sbin/gaming-qos": template("qos.sh.in", values),
        "/usr/local/sbin/gaming-monitor": template("monitor.sh.in", values).replace("8192", str(p["receive_kib"])),
        "/usr/local/sbin/gaming-receive-buffer": (ROOT/"runtime/receive-buffer.py").read_text(),
        "/usr/local/sbin/gaming-forward": forward_script(p).replace("@WAN@", wan),
    }
    endpoint = f"Endpoint = 127.0.0.1:{p['loopback_port']}\n" if p["role"] == "entry" else ""
    outputs[f"/etc/wireguard/{p['interface']}.conf"] = (
        f"[Interface]\nAddress = {p['link_local']}/30\nListenPort = {p['wg_port']}\n"
        f"PrivateKey = {private_key}\nMTU = {p['mtu']}\nTable = off\n"
        f"PostUp = /usr/local/sbin/gaming-address; ip route replace {p['service_peer']}/32 dev %i src {p['service_local']}; /usr/local/sbin/gaming-qos\n\n"
        f"[Peer]\nPublicKey = {p['peer_key']}\nAllowedIPs = {p['link_peer']}/32, {p['service_peer']}/32\n"
        f"{endpoint}PersistentKeepalive = 25\n")
    raw = (f"-c\n-l 127.0.0.1:{p['loopback_port']}\n-r {p['peer_public_ip']}:{p['carrier_id']}\n"
           if p["role"] == "entry" else
           f"-s\n-l {p['public_ip']}:{p['carrier_id']}\n-r 127.0.0.1:{p['wg_port']}\n")
    outputs[str(ETC/"carrier.conf")] = raw+f"-k {p['carrier_key']}\n--raw-mode icmp\n--cipher-mode aes128cbc\n--auth-mode hmac_sha1\n--log-level 3\n--disable-color\n"
    rule = f"-s {p['peer_public_ip']} -p icmp --icmp-type "+("echo-reply" if p["role"] == "entry" else "echo-request")
    outputs["/etc/systemd/system/gaming-raw.service"] = unit(
        "Gaming tunnel ICMP datagram carrier",
        "[Unit]\nAfter=systemd-sysctl.service netfilter-persistent.service ufw.service nftables.service\nStartLimitIntervalSec=0\n[Service]\n"
        f'ExecStartPre=/bin/sh -c "iptables -w -C INPUT {rule} -m comment --comment gaming-raw -j DROP 2>/dev/null || iptables -w -I INPUT 1 {rule} -m comment --comment gaming-raw -j DROP"\n'
        f"ExecStart={RAW} --conf-file {ETC/'carrier.conf'}\n"
        f"ExecStartPost=-/usr/bin/python3 /usr/local/sbin/gaming-receive-buffer {p['receive_kib']}\n"
        f"ExecStopPost=-/usr/sbin/iptables -w -D INPUT {rule} -m comment --comment gaming-raw -j DROP\n"
        "Restart=on-failure\nRestartSec=5\n[Install]\nWantedBy=multi-user.target\n")
    for name, description, start, stop in (
        ("gaming-address", "Stable gaming service address", "/usr/local/sbin/gaming-address", ""),
        ("gaming-forward", "Scoped gaming VPN forwarding", "/usr/local/sbin/gaming-forward up", "ExecStop=/usr/local/sbin/gaming-forward down\n")):
        ordering = (f"[Unit]\nWants=gaming-address.service gaming-raw.service wg-quick@{p['interface']}.service\n"
                    f"After=gaming-address.service gaming-raw.service wg-quick@{p['interface']}.service netfilter-persistent.service ufw.service nftables.service\n"
                    "StartLimitIntervalSec=0\n" if name == "gaming-forward" else "")
        retry = "Restart=on-failure\nRestartSec=10\n" if name == "gaming-forward" else ""
        outputs[f"/etc/systemd/system/{name}.service"] = unit(description,
            ordering+f"[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart={start}\n{stop}{retry}[Install]\nWantedBy=multi-user.target\n")
    outputs["/etc/systemd/system/gaming-monitor.service"] = unit("Gaming data-plane check",
        "[Service]\nType=oneshot\nExecStart=/usr/local/sbin/gaming-monitor\nTimeoutStartSec=45\n")
    outputs["/etc/systemd/system/gaming-monitor.timer"] = (
        "[Unit]\nDescription=Check gaming tunnel every 30 seconds\n[Timer]\nOnBootSec=60\n"
        "OnUnitInactiveSec=30\nAccuracySec=2\n[Install]\nWantedBy=timers.target\n")
    outputs[f"/etc/systemd/system/wg-quick@{p['interface']}.service.d/10-carrier.conf"] = (
        "[Unit]\nWants=gaming-raw.service gaming-address.service\nAfter=gaming-raw.service gaming-address.service\n"
        "StartLimitIntervalSec=0\n[Service]\nRestart=on-failure\nRestartSec=10\n")
    outputs["/etc/sysctl.d/90-gaming-tunnel.conf"] = "net.ipv4.ip_forward=1\n"
    return outputs

def audit():
    found = {"tcp": [], "udp": []}
    for line in run(["ss", "-H", "-lntu"]).stdout.splitlines():
        f = line.split()
        if len(f) < 5 or f[0] not in found:
            continue
        try:
            port = int(f[4].rsplit(":", 1)[1])
        except ValueError:
            continue
        if port in PORTS and (f[0] == "udp" or port in (46954, 48320)):
            found[f[0]].append(port)
    return dict(kernel=platform.release(), machine=platform.machine(),
                addresses=json.loads(run(["ip", "-j", "address"]).stdout),
                routes=json.loads(run(["ip", "-j", "route"]).stdout),
                vpn_ports={k: sorted(set(v)) for k,v in found.items()},
                ipv4_forwarding=Path("/proc/sys/net/ipv4/ip_forward").read_text().strip())

def prepare(payload):
    p = validate(payload["configuration"])
    if platform.machine() != "x86_64":
        raise RuntimeError("reference profile requires x86_64")
    existing = state()
    if not existing:
        conflicts = [ETC, LIB, Path("/etc/systemd/system/gaming-raw.service"),
                     Path("/usr/local/sbin/gaming-monitor"),
                     Path("/etc/wireguard")/(p["interface"]+".conf")]
        if any(x.exists() for x in conflicts) or run(["ip","link","show",p["interface"]],False).returncode == 0 or run(["ip","link","show","game-svc"],False).returncode == 0:
            raise RuntimeError("unmanaged gaming tunnel exists; refusing adoption or replacement")
    if payload.get("install_deps"):
        env = dict(os.environ, DEBIAN_FRONTEND="noninteractive", NEEDRESTART_MODE="l")
        code = subprocess.run(["apt-get","install","-y","--no-install-recommends","wireguard-tools","iproute2","iptables","ethtool"],
                              env=env,stdout=sys.stderr,stderr=sys.stderr).returncode
        if code:
            raise RuntimeError("dependency installation failed; update apt indexes separately")
    for cmd in ("wg","wg-quick","ip","iptables","tc","ss","python3","systemctl"):
        if not shutil.which(cmd):
            raise RuntimeError(f"missing dependency: {cmd}")
    for chain in ("INPUT","FORWARD"):
        if run(["iptables","-S",chain]).stdout.splitlines()[0] != "-P "+chain+" ACCEPT":
            raise RuntimeError("restrictive firewall requires explicit operator integration")
    if tuple(map(int,platform.release().split("-")[0].split(".")[:2])) < (5,6):
        raise RuntimeError("kernel 5.6 or newer required")
    run(["modprobe","sch_cake"])
    digest = hashlib.sha256((ROOT/"udp2raw").read_bytes()).hexdigest()
    if not re.fullmatch(r"[a-f0-9]{64}",payload["raw_sha256"]) or digest != payload["raw_sha256"]:
        raise RuntimeError("carrier binary checksum mismatch")
    if existing.get("phase") in ("applied","active"):
        if not RAW.exists() or hashlib.sha256(RAW.read_bytes()).hexdigest()!=digest:
            raise RuntimeError("refusing an in-place carrier upgrade")
        return {"public_key":run(["wg","pubkey"],data=(ETC/"private.key").read_text()).stdout.strip(),"audit":audit()}
    for d in (ETC,STATE,LIB):
        d.mkdir(mode=0o700,parents=True,exist_ok=True)
    if not (ETC/"private.key").exists():
        write(ETC/"private.key",run(["wg","genkey"]).stdout)
    for name in ("agent.py","model.py","udp2raw"):
        if name=="udp2raw" and (LIB/name).exists():
            if hashlib.sha256((LIB/name).read_bytes()).hexdigest()==digest:
                continue
            if existing.get("phase") in ("applied","active"):
                raise RuntimeError("refusing to replace active carrier binary")
        if (ROOT/name).resolve() != (LIB/name).resolve():
            shutil.copyfile(ROOT/name,LIB/name)
        os.chmod(LIB/name,0o600 if name=="model.py" else 0o700)
    shutil.copytree(ROOT/"runtime",LIB/"runtime",dirs_exist_ok=True)
    if not existing:
        save_state(dict(phase="prepared",interface=p["interface"]))
    pub = run(["wg","pubkey"],data=(ETC/"private.key").read_text()).stdout.strip()
    return {"public_key":pub,"audit":audit()}

def snapshot(tag, outputs, p):
    if not re.fullmatch(r"[a-f0-9]{16}",tag):
        raise ValueError("invalid transaction id")
    b = STATE/"transactions"/tag
    b.mkdir(mode=0o700,parents=True,exist_ok=False)
    entries = []
    for i,name in enumerate(outputs):
        path = Path(name)
        if path.is_symlink():
            raise RuntimeError("refusing a symlink target")
        entry = {"path":name,"existed":path.exists(),"backup":str(i)}
        if path.exists():
            shutil.copy2(path,b/str(i))
        entries.append(entry)
    write(b/"manifest.json",json.dumps(dict(files=entries,interface=p["interface"],state=state(),
          ip_forward=Path("/proc/sys/net/ipv4/ip_forward").read_text().strip(),
          rmem_max=Path("/proc/sys/net/core/rmem_max").read_text().strip())))
    return b

def apply(payload):
    p = checked_plan(payload["plan"])
    s = state()
    if not s or s.get("interface") != p["interface"]:
        raise RuntimeError("run prepare before apply")
    key = (ETC/"private.key").read_text().strip()
    route = json.loads(run(["ip","-j","route","get",p["peer_public_ip"]]).stdout)
    if not route or route[0]["dev"] == p["interface"]:
        raise RuntimeError("peer endpoint must use independent public routing")
    outputs = render(p,key,route[0]["dev"])
    rmem_max = max(int(Path("/proc/sys/net/core/rmem_max").read_text()),p["receive_kib"]*1024)
    outputs["/etc/sysctl.d/90-gaming-tunnel.conf"] += "net.core.rmem_max="+str(rmem_max)+"\n"
    fingerprint = hashlib.sha256(json.dumps(outputs,sort_keys=True).encode()).hexdigest()
    if s.get("phase") in ("applied","active"):
        if s.get("fingerprint") != fingerprint:
            raise RuntimeError("managed config differs; use a maintenance migration, not live overwrite")
        return {"noop":True,"transaction":s["transaction"]}
    if any(Path(f).exists() for f in outputs):
        raise RuntimeError("unmanaged target files exist; refusing overwrite")
    for table,chain in (("nat","GAME_DNAT"),("nat","GAME_SNAT"),("filter","GAME_L2TP"),("mangle","GAME_L2TP_MSS")):
        if run(["iptables","-t",table,"-S",chain],False).returncode == 0:
            raise RuntimeError("existing firewall chain has no ownership record")
    tag = payload["transaction"]
    snapshot(tag,outputs,p)
    run(["systemd-run","--unit=gaming-rollback-"+tag,"--on-active=15m",
         "/usr/bin/python3",str(LIB/"agent.py"),"rollback",tag])
    for name,content in outputs.items():
        mode = 0o700 if name.startswith("/usr/local/sbin/") else 0o600
        write(name,content,0o644 if name.startswith("/etc/systemd/") else mode)
    run(["systemctl","daemon-reload"])
    run(["sysctl","-w","net.core.rmem_max="+str(rmem_max)])
    run(["sysctl","-w","net.ipv4.ip_forward=1"])
    for name in ("gaming-address","gaming-raw","wg-quick@"+p["interface"]):
        run(["systemctl","enable","--now",name])
    save_state(dict(phase="applied",interface=p["interface"],fingerprint=fingerprint,
                    transaction=tag,service_peer=p["service_peer"],profile={k:v for k,v in p.items() if k!="carrier_key"}))
    return {"transaction":tag,"phase":"applied"}

def health():
    s = state()
    if not s.get("service_peer"):
        raise RuntimeError("no configured tunnel")
    run(["ping","-n","-q","-c","5","-i","0.3","-W","2",s["service_peer"]])
    run(["python3","/usr/local/sbin/gaming-receive-buffer",str(s["profile"]["receive_kib"])])
    for name in ("gaming-raw","wg-quick@"+s["interface"]):
        run(["systemctl","is-active","--quiet",name])
    return {"healthy":True,"interface":s["interface"]}

def activate():
    health()
    for name in ("gaming-forward","gaming-monitor.timer"):
        run(["systemctl","enable","--now",name])
    s = state()
    s["phase"] = "active"
    save_state(s)
    return {"phase":"active"}

def commit(tag):
    run(["systemctl","stop","gaming-rollback-"+tag+".timer"],False)
    return {"committed":True}

def rollback(tag):
    b = STATE/"transactions"/tag
    if not (b/"manifest.json").exists():
        return {"noop":True}
    m = json.loads((b/"manifest.json").read_text())
    for name in UNITS:
        run(["systemctl","disable","--now",name.format(iface=m["interface"])],False)
    if Path("/usr/local/sbin/gaming-forward").exists():
        run(["/usr/local/sbin/gaming-forward","down"],False)
    run(["ip","link","delete","game-svc"],False)
    for e in m["files"]:
        target = Path(e["path"])
        if e["existed"]:
            shutil.copy2(b/e["backup"],target)
        elif target.exists():
            target.unlink()
    run(["sysctl","-w","net.ipv4.ip_forward="+m["ip_forward"]])
    run(["sysctl","-w","net.core.rmem_max="+m["rmem_max"]])
    run(["systemctl","daemon-reload"])
    save_state(m["state"])
    run(["systemctl","stop","gaming-rollback-"+tag+".timer"],False)
    return {"rolled_back":tag}

def repair_l2tp():
    """Explicit opt-in reference repair; never read passwords/databases."""
    profile = state().get("profile")
    if state().get("phase")!="active" or not profile:
        raise RuntimeError("deploy the owned tunnel before the opt-in repair")
    p,opts = Path("/etc/ipsec.conf"),Path("/etc/ppp/options.xl2tpd")
    if not p.is_file() or not opts.is_file():
        raise RuntimeError("reference strongSwan/xl2tpd layout not found")
    b = STATE/"l2tp-backups"/str(time.time_ns())
    b.mkdir(parents=True,mode=0o700)
    for f in (p,opts):
        shutil.copy2(f,b/f.name)
    text = p.read_text().replace("ike=aes256-sha1-modp1024,3des-sha1-modp1024!",
            "ike=aes256-sha256-modp2048,aes256-sha1-modp1024,3des-sha1-modp1024!")
    text = text.replace("esp=aes256-sha1,3des-sha1!","esp=aes256-sha256,aes256-sha1,3des-sha1!")
    if "aes256-sha256-modp2048" not in text:
        raise RuntimeError("custom IPsec proposals require manual review")
    text_opts = opts.read_text()
    for k,v in dict(mtu=profile["l2tp_mtu"],mru=profile["l2tp_mtu"],**{"lcp-echo-interval":10,"lcp-echo-failure":6}).items():
        text_opts,n = re.subn(r"(?m)^"+re.escape(k)+r"\s+\d+\s*$",f"{k} {v}",text_opts)
        if not n:
            text_opts += f"\n{k} {v}\n"
    write(p,text)
    write(opts,text_opts)
    run(["ipsec","update"])
    return {"l2tp_profile_applied":True,"backup":str(b),"note":"new PPP sessions negotiate the new MTU; no VPN restart"}


def bench_payload(payload):
    tag = payload["tag"]
    if not re.fullmatch(r"[a-f0-9]{16}",tag):
        raise ValueError("invalid benchmark id")
    for name,low,high in (("seconds",30,1800),("tcp_mbit",1,40),("udp_mbit",1,2)):
        if type(payload[name]) is not int or not low<=payload[name]<=high:
            raise ValueError("benchmark outside protected limits")
    s = state()
    if s.get("phase")!="active":
        raise RuntimeError("benchmark requires an active owned deployment")
    p = s["profile"]
    b = STATE/"bench"/tag
    b.mkdir(parents=True,mode=0o700,exist_ok=True)
    return tag,p,b

def bench_servers(payload):
    tag,p,b = bench_payload(payload)
    base = 52103 if p["role"]=="entry" else 52101
    listeners = run(["ss","-H","-lnt"]).stdout
    if any(re.search(r":"+str(port)+r"\s",listeners) for port in (base,base+1)):
        raise RuntimeError("benchmark port already occupied")
    if not shutil.which("iperf3"):
        raise RuntimeError("install iperf3 explicitly on both servers before a soak")
    for name,port in (("tcp",base),("udp",base+1)):
        run(["systemd-run","--unit=gaming-test-"+tag+"-"+name,
             "--property=RuntimeMaxSec="+str(payload["seconds"]+120),
             "--property=StandardOutput=append:"+str(b/(name+"-receiver.log")),
             "--property=StandardError=append:"+str(b/(name+"-receiver.log")),
             "/usr/bin/stdbuf","-oL","iperf3","-s","-1","-B",p["link_local"],"-p",str(port)])
    return {"benchmark":tag,"servers_ready":True}

def bench_start(payload):
    tag,p,b = bench_payload(payload)
    base = 52101 if p["role"]=="entry" else 52103
    run(["systemd-run","--unit=gaming-test-"+tag+"-monitor",
         "--property=RuntimeMaxSec="+str(payload["seconds"]+90),
         "--property=StandardOutput=append:"+str(b/"supervisor.log"),
         "--property=StandardError=append:"+str(b/"supervisor.log"),
         "/usr/bin/python3",str(LIB/"runtime/soak.py"),"--directory",str(b),
         "--peer",p["link_peer"],"--tcp-port",str(base),"--udp-port",str(base+1),
         "--role",p["role"],"--seconds",str(payload["seconds"]),
         "--tcp-mbit",str(payload["tcp_mbit"]),"--udp-mbit",str(payload["udp_mbit"])])
    return {"started":tag}

def bench_status(tag):
    path = STATE/"bench"/tag/"status.json"
    return json.loads(path.read_text()) if path.exists() else {"starting":True}

def bench_stop(tag):
    for name in ("monitor","tcp","udp"):
        run(["systemctl","stop","gaming-test-"+tag+"-"+name],False)
    return {"test_jobs_stopped":tag}


def main():
    if sys.platform != "linux":
        raise RuntimeError("the privileged host agent requires Linux")
    import fcntl
    ap = argparse.ArgumentParser()
    ap.add_argument("action",choices=("prepare","audit","apply","activate","health","commit","rollback","repair-l2tp","bench-servers","bench-start","bench-status","bench-stop"))
    ap.add_argument("transaction",nargs="?")
    args = ap.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("root required")
    with open("/run/gaming-tunnel.lock","w") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX)
        if args.action in ("prepare","apply","bench-servers","bench-start"):
            payload = json.load(sys.stdin)
            result = {"prepare":prepare,"apply":apply,"bench-servers":bench_servers,"bench-start":bench_start}[args.action](payload)
        elif args.action in ("commit","rollback","bench-status","bench-stop"):
            if not args.transaction or not re.fullmatch(r"[a-f0-9]{16}",args.transaction):
                raise ValueError("transaction id required")
            result = {"commit":commit,"rollback":rollback,"bench-status":bench_status,"bench-stop":bench_stop}[args.action](args.transaction)
        else:
            result = {"audit":audit,"activate":activate,"health":health,"repair-l2tp":repair_l2tp}[args.action]()
    print(json.dumps(result))

if __name__=="__main__":
    try:
        main()
    except Exception as exc:
        print(f"ERROR: {exc}",file=sys.stderr)
        sys.exit(1)
