#!/usr/bin/env python3
"""Resumable, bounded parallel HTTP download with a required trusted digest."""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import re
import time
import urllib.request

def fetch(url, output, expected, algorithm="sha512", workers=8):
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    if not re.fullmatch("[0-9a-f]+", expected) or len(expected) != hashlib.new(algorithm).digest_size*2:
        raise ValueError("invalid expected digest")
    def digest(path):
        h=hashlib.new(algorithm)
        with path.open("rb") as f:
            for b in iter(lambda:f.read(1<<20),b""):h.update(b)
        return h.hexdigest()
    if output.exists() and digest(output)==expected:
        return {"path":str(output),"digest":expected,"bytes":output.stat().st_size,"cached":True}
    req=urllib.request.Request(url,headers={"Range":"bytes=0-0","User-Agent":"nextgen-local-lab"})
    with urllib.request.urlopen(req,timeout=20) as r:
        match=re.fullmatch(r"bytes 0-0/(\d+)",r.headers.get("Content-Range",""))
        if not match:raise ValueError("server must support byte ranges")
        size=int(match.group(1));r.read()
    chunk=2*1024*1024
    parts=output.with_name(output.name+".parts");parts.mkdir(exist_ok=True)
    def part(i):
        start=i*chunk;end=min(size,start+chunk)-1;path=parts/str(i)
        if path.exists() and path.stat().st_size==end-start+1:return path
        for attempt in range(8):
            try:
                request=urllib.request.Request(url,headers={"Range":f"bytes={start}-{end}","User-Agent":"nextgen-local-lab"})
                with urllib.request.urlopen(request,timeout=25) as r:
                    if r.headers.get("Content-Range")!=f"bytes {start}-{end}/{size}":raise ValueError("range mismatch")
                    data=r.read(end-start+2)
                if len(data)!=end-start+1:raise ValueError("truncated range")
                path.write_bytes(data);return path
            except (OSError,ValueError):
                if attempt==7:raise
                time.sleep(min(3,attempt+1))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        paths=list(pool.map(part,range((size+chunk-1)//chunk)))
    pending=output.with_name(output.name+".pending")
    with pending.open("wb") as f:
        for path in paths:
            with path.open("rb") as p:
                for b in iter(lambda:p.read(1<<20),b""):f.write(b)
    if digest(pending)!=expected:raise ValueError("download integrity mismatch")
    pending.replace(output)
    return {"path":str(output),"digest":expected,"bytes":size,"url":url}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("url");p.add_argument("output",type=Path);p.add_argument("--digest",required=True);p.add_argument("--algorithm",choices=("sha256","sha512"),default="sha512");p.add_argument("--workers",type=int,default=8);a=p.parse_args()
    if not 1<=a.workers<=16:p.error("workers must be 1..16")
    print(json.dumps(fetch(a.url,a.output,a.digest,a.algorithm,a.workers)),flush=True)
if __name__=="__main__":main()
