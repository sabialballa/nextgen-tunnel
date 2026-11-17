#!/usr/bin/env python3
"""Explicit, offline, scoped installation of a locally verified release.

No firewall, route, sysctl, existing VPN or SSH configuration is changed.
Every replacement is journaled before mutation. Recovery is explicit on crash.
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

ROOT = Path(__file__).resolve().parents[1]
FILES = ("/usr/local/bin/nextgen-tunnel", "/etc/nextgen-tunnel/config.json",
         "/etc/nextgen-tunnel/ca.crt", "/etc/nextgen-tunnel/cert.crt",
         "/etc/nextgen-tunnel/endpoint.key", "/etc/systemd/system/nextgen-tunnel.service")
STATE = Path("/var/lib/nextgen-tunnel-installer")
RUNTIME = Path("/var/lib/nextgen-tunnel")
MARKER = STATE / "ownership.json"
JOURNAL = STATE / "transaction.json"
ACCOUNT = STATE / "account.json"

def run(args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=30)

def safe_path(path):
    path = Path(path)
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError("symlink in managed path")
    if path.exists() and not path.is_file():
        raise ValueError("managed target is not a regular file")
    return path

def atomic(path, data, mode=0o600):
    path = safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".nextgen-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)

def read_marker():
    if not MARKER.exists():
        return None
    safe_path(MARKER)
    return json.loads(MARKER.read_text())

def secure_state():
    if any(p.is_symlink() for p in (STATE, *STATE.parents)):
        raise ValueError("symlink in installer state path")
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    st = STATE.stat()
    if st.st_uid != 0 or st.st_mode & 0o022:
        raise ValueError("installer state must be root-owned and not writable by other users")

def content(args):
    binary = safe_path(args.binary).read_bytes()
    if not re.fullmatch(r"[a-fA-F0-9]{64}", args.sha256 or ""):
        raise ValueError("a trusted SHA256 is required")
    if hashlib.sha256(binary).hexdigest() != args.sha256.lower():
        raise ValueError("binary integrity mismatch")
    arch = {"x86_64": 62, "aarch64": 183}.get(platform.machine())
    if len(binary) < 20 or binary[:6] != b"\x7fELF\x02\x01" or int.from_bytes(binary[18:20], "little") != arch:
        raise ValueError("binary is not a matching Linux ELF64 executable")
    cfg = json.loads(safe_path(args.config).read_text())
    if cfg.get("role") not in ("server", "client"):
        raise ValueError("invalid role")
    result = {FILES[0]: binary}
    for key, target in (("ca", FILES[2]), ("cert", FILES[3]), ("key", FILES[4])):
        result[target] = safe_path(cfg["tls"][key]).read_bytes()
        cfg["tls"][key] = target
    cfg["status_file"] = str(RUNTIME / "status.json") if cfg["role"] == "client" else ""
    result[FILES[1]] = (json.dumps(cfg, indent=2) + "\n").encode()
    result[FILES[5]] = (ROOT / "systemd/nextgen-tunnel.service").read_bytes()
    return result

def fingerprint(files):
    return {k: hashlib.sha256(v).hexdigest() for k, v in files.items()}

def preflight():
    if sys.platform != "linux":
        raise ValueError("installation requires Linux with systemd")
    release = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text().splitlines() if "=" in line)
    distro, version = (release.get(k, "").strip('"') for k in ("ID", "VERSION_ID"))
    if (distro, version) not in (("ubuntu", "22.04"), ("ubuntu", "24.04"), ("debian", "12"), ("debian", "13")):
        raise ValueError("unsupported distribution/version")
    if not Path("/run/systemd/system").exists():
        raise ValueError("systemd is not running")
    for tool in ("systemctl", "ss", "ip", "runuser", "useradd"):
        if not shutil.which(tool):
            raise ValueError(f"missing prerequisite: {tool}")
    # Read-only inventory; no credentials or configuration file dumps.
    checks = (("listeners", ["ss", "-H", "-lntu"]),
              ("routes", ["ip", "-j", "route", "show"]),
              ("active_services", ["systemctl", "list-units", "--type=service", "--state=running", "--no-pager"]),
              ("ssh", ["systemctl", "is-active", "ssh.service", "sshd.service"]))
    report = {"distribution": distro, "version": version, "architecture": platform.machine(),
              "timestamp": time.time(), "firewall_changes": False, "route_changes": False}
    for key, cmd in checks:
        r = run(cmd, check=False)
        report[key] = {"returncode": r.returncode, "stdout": r.stdout}
    if shutil.which("nft"):
        r = run(["nft", "list", "ruleset"], check=False)
        report["firewall"] = {"returncode": r.returncode, "stdout": r.stdout}
    else:
        report["firewall"] = "nft unavailable; manual firewall inspection required"
    return report

def snapshot(files, report):
    backup = STATE / ("backup-" + str(time.time_ns()))
    backup.mkdir(mode=0o700)
    records = []
    for i, name in enumerate(files):
        p = safe_path(name)
        record = {"path": name, "existed": p.exists(), "backup": str(i)}
        if p.exists():
            shutil.copy2(p, backup / str(i))
            record.update(mode=p.stat().st_mode & 0o777, uid=p.stat().st_uid, gid=p.stat().st_gid)
        records.append(record)
    active = run(["systemctl", "is-active", "--quiet", "nextgen-tunnel"], False).returncode == 0
    enabled = run(["systemctl", "is-enabled", "--quiet", "nextgen-tunnel"], False).returncode == 0
    data = dict(files=records, backup=str(backup), active=active, enabled=enabled, previous=read_marker())
    atomic(backup / "preflight.json", json.dumps(report, indent=2).encode())
    atomic(JOURNAL, json.dumps(data).encode())
    return data

def restore(journal):
    # The journal is root-owned, and every path must match the fixed allowlist.
    if set(x["path"] for x in journal["files"]) != set(FILES):
        raise ValueError("invalid recovery journal paths")
    backup = Path(journal["backup"])
    if backup.parent != STATE or not backup.name.startswith("backup-"):
        raise ValueError("invalid recovery backup")
    run(["systemctl", "stop", "nextgen-tunnel"], False)
    if not journal["enabled"]:
        run(["systemctl", "disable", "nextgen-tunnel"], False)
    for item in journal["files"]:
        p = safe_path(item["path"])
        if item["existed"]:
            src = safe_path(backup / item["backup"])
            atomic(p, src.read_bytes(), item["mode"])
            os.chown(p, item["uid"], item["gid"])
        elif p.exists():
            p.unlink()
    if journal["previous"]:
        atomic(MARKER, json.dumps(journal["previous"]).encode())
    elif MARKER.exists():
        MARKER.unlink()
    run(["systemctl", "daemon-reload"])
    if journal["enabled"]:
        run(["systemctl", "enable", "nextgen-tunnel"], False)
    if journal["active"]:
        run(["systemctl", "start", "nextgen-tunnel"])
    JOURNAL.unlink()

def apply(args, files, report):
    import pwd
    old = read_marker()
    if JOURNAL.exists():
        raise ValueError("unfinished transaction; run host_install.py recover --apply first")
    for path in FILES:
        safe_path(path)
    if not old and any(Path(p).exists() for p in FILES):
        raise ValueError("unmanaged files exist; refusing overwrite")
    if args.action == "update" and not old:
        raise ValueError("update requires an owned installation")
    if old:
        for name, digest in old["hashes"].items():
            if name not in FILES or not Path(name).exists() or hashlib.sha256(Path(name).read_bytes()).hexdigest() != digest:
                raise ValueError("managed files changed outside installer; refusing overwrite")
        if old["hashes"] == fingerprint(files):
            run(["systemctl", "is-active", "--quiet", "nextgen-tunnel"])
            return "unchanged; service active"
        if args.action != "update":
            raise ValueError("configuration differs; use update explicitly")
    secure_state()
    try:
        user = pwd.getpwnam("nextgen-tunnel")
        if not old and (not ACCOUNT.exists() or json.loads(ACCOUNT.read_text()).get("uid") != user.pw_uid):
            raise ValueError("existing service account has no ownership record")
    except KeyError:
        run(["useradd", "--system", "--user-group", "--no-create-home", "--shell", "/usr/sbin/nologin", "nextgen-tunnel"])
        user = pwd.getpwnam("nextgen-tunnel")
        atomic(ACCOUNT, json.dumps({"uid": user.pw_uid}).encode())
    # Service account/empty directories are intentionally retained after rollback.
    journal = snapshot(files, report)
    try:
        for path, data in files.items():
            atomic(path, data, 0o755 if path == FILES[0] else 0o644 if path == FILES[5] else 0o600)
            if path.startswith("/etc/nextgen-tunnel/"):
                os.chown(path, user.pw_uid, user.pw_gid)
        os.chmod("/etc/nextgen-tunnel", 0o750)
        os.chown("/etc/nextgen-tunnel", 0, user.pw_gid)
        run(["runuser", "-u", "nextgen-tunnel", "--", FILES[0], "check", "-config", FILES[1]])
        run(["systemctl", "daemon-reload"])
        run(["systemctl", "enable", "nextgen-tunnel"])
        run(["systemctl", "restart", "nextgen-tunnel"])
        time.sleep(2)
        run(["systemctl", "is-active", "--quiet", "nextgen-tunnel"])
        if json.loads(files[FILES[1]])["role"] == "client":
            run(["runuser", "-u", "nextgen-tunnel", "--", FILES[0], "probe", "-config", FILES[1]])
        atomic(MARKER, json.dumps({"hashes": fingerprint(files), "backup": journal["backup"]}).encode())
        JOURNAL.unlink()
        return "installed; service active; server role still requires a remote authenticated probe"
    except BaseException:
        restore(journal)
        raise

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("install", "update", "uninstall", "recover"))
    p.add_argument("--binary", type=Path)
    p.add_argument("--sha256")
    p.add_argument("--config", type=Path)
    p.add_argument("--apply", action="store_true", help="perform the reviewed operation")
    a = p.parse_args()
    report = preflight()
    if a.action in ("install", "update"):
        if not a.binary or not a.config:
            p.error("--binary, --sha256 and --config are required")
        files = content(a)
    else:
        files = None
    if not a.apply:
        print(json.dumps(dict(preflight=report, action=a.action, managed_paths=FILES, changes_applied=False), indent=2))
        return
    if os.geteuid() != 0:
        raise ValueError("--apply requires root")
    secure_state()
    if a.action == "recover":
        if JOURNAL.exists():
            restore(json.loads(JOURNAL.read_text()))
        print("recovery complete")
    elif a.action == "uninstall":
        old = read_marker()
        if not old:
            print("no owned installation")
            return
        if JOURNAL.exists():
            raise ValueError("recover unfinished transaction before uninstall")
        for name, digest in old["hashes"].items():
            if name not in FILES or hashlib.sha256(safe_path(name).read_bytes()).hexdigest() != digest:
                raise ValueError("modified managed file; refusing uninstall")
        journal = snapshot(FILES, report)
        try:
            run(["systemctl", "disable", "--now", "nextgen-tunnel"])
            for name in FILES:
                safe_path(name).unlink()
            MARKER.unlink()
            run(["systemctl", "daemon-reload"])
            JOURNAL.unlink()
        except BaseException:
            restore(journal)
            raise
        print("owned files removed; backups, state and service account retained")
    else:
        print(apply(a, files, report))

if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.SubprocessError, KeyError) as exc:
        print(f"installation failed: {exc}", file=sys.stderr)
        sys.exit(1)
