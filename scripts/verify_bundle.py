#!/usr/bin/env python3
"""Read-only archive checks: safe paths, complete manifest and member integrity."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import zipfile

def verify(path):
    entries = {}
    total = 0
    def add(name, size, reader):
        nonlocal total
        parts = PurePosixPath(name).parts
        if not parts or name.startswith("/") or ".." in parts or "\\" in name or ":" in name:
            raise ValueError("unsafe archive path")
        if len(parts) < 2 or name in entries or size > 128 * 1024**2:
            raise ValueError("duplicate or oversized member")
        if any(p in (".private", "deployment-records", ".git", "__pycache__") for p in parts) or PurePosixPath(name).suffix in (".key", ".pem", ".crt", ".pcap"):
            raise ValueError("private file in bundle")
        total += size
        if total > 256 * 1024**2 or len(entries) >= 2000:
            raise ValueError("archive exceeds verification budget")
        data = reader.read(size + 1)
        if len(data) != size: raise ValueError("invalid member size")
        entries[name] = data
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                if info.is_dir(): continue
                mode = info.external_attr >> 16
                if mode & 0o170000 == 0o120000: raise ValueError("archive symlink")
                with z.open(info) as f: add(info.filename, info.file_size, f)
    else:
        with tarfile.open(path, "r:gz") as t:
            for info in t:
                if not info.isfile(): raise ValueError("archive contains a non-regular entry")
                with t.extractfile(info) as f: add(info.name, info.size, f)
    prefixes = {PurePosixPath(name).parts[0] for name in entries}
    if len(prefixes) != 1: raise ValueError("inconsistent bundle root")
    prefix = next(iter(prefixes)) + "/"
    manifest_path = prefix + "SHA256SUMS"
    manifest = entries.pop(manifest_path).decode("ascii")
    expected = {}
    for line in manifest.splitlines():
        digest, name = line.split("  ",1)
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or name in expected:
            raise ValueError("invalid manifest")
        expected[name] = digest
    actual = {name[len(prefix):]: hashlib.sha256(data).hexdigest() for name, data in entries.items()}
    if actual != expected: raise ValueError("member checksum or manifest coverage mismatch")
    return {"bundle":path.name,"sha256":hashlib.sha256(path.read_bytes()).hexdigest(),"verified_members":len(actual),"uncompressed_bytes":total}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("bundles", nargs="+", type=Path)
    args = p.parse_args()
    for path in args.bundles: print(json.dumps(verify(path)))

if __name__ == "__main__": main()
