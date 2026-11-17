#!/usr/bin/env python3
"""Build a pinned, patched optional engine; never install an unchecked download."""
import argparse
import hashlib
import json
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
COMMIT='c005f35300ce76427dc285481ec5695f5b179cd2'
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--go',default='go');p.add_argument('--output',type=Path,required=True);p.add_argument('--arch',choices=('amd64','arm64'),default='amd64');a=p.parse_args()
    output=a.output.resolve();output.parent.mkdir(parents=True,exist_ok=True);patch=ROOT/'patches/sing-box-v1.14.4-dependencies.patch'
    go=str(Path(a.go).resolve()) if Path(a.go).exists() else a.go
    def run(args,**kw):return subprocess.run(args,check=True,capture_output=True,text=True,**kw).stdout
    with tempfile.TemporaryDirectory(prefix='nextgen-engine-build-') as tmp:
        source=Path(tmp)/'source';run(['git','clone','--depth','1','--branch','v1.14.4','https://github.com/SagerNet/sing-box.git',str(source)])
        if run(['git','-C',str(source),'rev-parse','HEAD']).strip()!=COMMIT:raise ValueError('upstream tag changed')
        run(['git','-C',str(source),'apply',str(patch)])
        env=dict(os.environ,GOOS='linux',GOARCH=a.arch,CGO_ENABLED='0',GOMAXPROCS='2',GOTOOLCHAIN='local')
        run([go,'-C',str(source),'mod','verify'],env=env)
        run([go,'-C',str(source),'build','-trimpath','-tags','with_quic,with_utls','-ldflags=-checklinkname=0','-o',str(output),'./cmd/sing-box'],env=env)
        # Keep exact dependency graph and license alongside the local binary.
        for name in ('go.mod','go.sum','LICENSE'):shutil.copyfile(source/name,output.with_name(output.name+'.'+name))
    report=dict(upstream='https://github.com/SagerNet/sing-box.git',commit=COMMIT,patch_sha256=hashlib.sha256(patch.read_bytes()).hexdigest(),go=run([go,'version']).strip(),tags=['with_quic','with_utls'],os='linux',arch=a.arch,binary_sha256=hashlib.sha256(output.read_bytes()).hexdigest(),security_scan_required=True)
    output.with_suffix('.build.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))
if __name__=='__main__':main()
