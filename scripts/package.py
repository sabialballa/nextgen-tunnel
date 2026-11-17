#!/usr/bin/env python3
"""Create an offline bundle from a source allowlist, never the whole workspace."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DIRECTORIES = ("cmd", "internal", "scripts", "systemd", "configs/examples", "tests", "docs")
TOP = ("go.mod", "go.sum", "README.md", "NEXTGEN.md", "LICENSE", "THIRD_PARTY_NOTICES.md", "agent.py", "model.py", "tunnelctl.py", "deployment.example.json", ".gitignore", ".gitattributes", ".github/workflows/checks.yml", ".github/workflows/nextgen.yml", "patches/sing-box-v1.14.4-dependencies.patch")

def sources():
    paths = [ROOT / p for p in TOP]
    for directory in DIRECTORIES + ("runtime",):
        paths.extend(p for p in (ROOT / directory).rglob("*")
                     if p.is_file() and p.name != 'CONTINUE.md' and p.suffix in (".go", ".py", ".sh", ".service", ".timer", ".json", ".md", ".in", ".txt"))
    return sorted(set(paths))

def audit(paths):
    findings = []
    for path in paths:
        if path.is_symlink() or "__pycache__" in path.parts or path.suffix in (".key", ".pem", ".crt", ".pcap"):
            findings.append(str(path.relative_to(ROOT)))
            continue
        data = path.read_bytes()
        if path.suffix == '.json':
            def contains_secret(value):
                if isinstance(value,dict):
                    return any((k in ('password','private_key','reality_private_key','carrier_key','token') and bool(v)) or contains_secret(v) for k,v in value.items())
                if isinstance(value,list):return any(contains_secret(v) for v in value)
                return False
            if contains_secret(json.loads(data)):
                findings.append(str(path.relative_to(ROOT)))
        if re.search(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", data) or re.search(rb"\b(?:ghp|gho|ghu|ghs)_[A-Za-z0-9]{30,}\b", data):
            findings.append(str(path.relative_to(ROOT)))
    if findings:
        raise ValueError("possible secret or unsafe file in allowlist: " + ", ".join(findings))

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", required=True, type=Path)
    p.add_argument("--os", required=True, choices=("linux", "windows"))
    p.add_argument("--arch", required=True, choices=("amd64", "arm64"))
    p.add_argument("--version", default="0.3.0-rc3")
    p.add_argument("--engine", type=Path, help="optional Linux amd64 engine binary")
    p.add_argument("--engine-source", type=Path, help="matching offline corresponding-source archive")
    p.add_argument("--engine-license", type=Path, help="upstream engine license")
    p.add_argument("--output", type=Path, default=ROOT / "dist")
    a = p.parse_args()
    if not re.fullmatch(r"[0-9][A-Za-z0-9_.-]{0,40}", a.version):
        p.error("invalid version")
    paths = sources(); audit(paths)
    files = {str(path.relative_to(ROOT)).replace("\\", "/"): path.read_bytes() for path in paths}
    binary_name = "bin/nextgen-tunnel" + (".exe" if a.os == "windows" else "")
    files[binary_name] = a.binary.read_bytes()
    if any((a.engine,a.engine_source,a.engine_license)):
        if not all((a.engine,a.engine_source,a.engine_license)) or (a.os,a.arch)!=('linux','amd64'):
            p.error('engine, corresponding source and license required together for Linux amd64')
        engine=a.engine.read_bytes(); source=a.engine_source.read_bytes()
        if hashlib.sha256(engine).hexdigest()!='606f883d1aa3c624f38aa3f99bf0df02e3999f9aa0ff5826e0dd9c1b9f964baf':
            p.error('engine does not match the reproduced and scanned build')
        if hashlib.sha256(source).hexdigest()!='5213527438d5c950c772d071fcd360e9d9954754efa92d7cab56dafaa2b34899':
            p.error('corresponding source does not match the offline reproduction')
        files['bin/sing-box']=engine
        files['engine-source/'+a.engine_source.name]=source
        files['licenses/sing-box-LICENSE']=a.engine_license.read_bytes()
    files["SHA256SUMS"] = ("\n".join(hashlib.sha256(data).hexdigest() + "  " + name for name, data in sorted(files.items())) + "\n").encode()
    prefix = f"nextgen-tunnel-{a.version}-{a.os}-{a.arch}"
    if a.engine:prefix+='-full'
    a.output.mkdir(parents=True, exist_ok=True)
    target = a.output / (prefix + (".zip" if a.os == "windows" else ".tar.gz"))
    if a.os == "windows":
        with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as z:
            for name, data in sorted(files.items()):
                z.writestr(prefix + "/" + name, data)
    else:
        with tarfile.open(target, "w:gz") as t:
            for name, data in sorted(files.items()):
                info = tarfile.TarInfo(prefix + "/" + name)
                info.size = len(data); info.mtime = 0
                info.mode = 0o755 if name in (binary_name,'bin/sing-box') or name.endswith(".sh") else 0o644
                t.addfile(info, io.BytesIO(data))
    checksum = hashlib.sha256(target.read_bytes()).hexdigest()
    target.with_name(target.name + ".sha256").write_text(checksum + "  " + target.name + "\n")
    print(str(target.resolve()))
    print(checksum)

if __name__ == "__main__": main()
