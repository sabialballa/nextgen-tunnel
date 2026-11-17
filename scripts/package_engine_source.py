#!/usr/bin/env python3
"""Archive exact optional-engine source and used Go modules for offline rebuilding.

Only tracked public upstream source and sanitized public Git metadata are copied.
The application's private deployment directory is never an input.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile

COMMIT='c005f35300ce76427dc285481ec5695f5b179cd2'
ENGINE_SHA='606f883d1aa3c624f38aa3f99bf0df02e3999f9aa0ff5826e0dd9c1b9f964baf'

def objects(text):
    decoder=json.JSONDecoder();index=0
    while index<len(text):
        while index<len(text) and text[index].isspace():index+=1
        if index==len(text):break
        value,index=decoder.raw_decode(text,index);yield value

def main():
    p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--go',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();source=a.source.resolve();go=str(Path(a.go).resolve());env=dict(os.environ,GOOS='linux',GOARCH='amd64',CGO_ENABLED='0',GOTOOLCHAIN='local',GOPROXY='off')
    def run(args):return subprocess.check_output(args,cwd=source,env=env,text=True,encoding='utf-8')
    if run(['git','rev-parse','HEAD']).strip()!=COMMIT:raise ValueError('wrong upstream revision')
    if run(['git','remote','get-url','origin']).strip()!='https://github.com/SagerNet/sing-box.git':raise ValueError('official source required')
    if set(run(['git','diff','--name-only','HEAD']).split())-{'go.mod','go.sum'}:raise ValueError('unexpected source edits')
    packages=list(objects(run([go,'list','-mod=readonly','-tags','with_quic,with_utls','-deps','-json','./cmd/sing-box'])));modules={}
    for pkg in packages:
        module=pkg.get('Module')
        if module and not module.get('Main'):
            module=module.get('Replace',module);modules[(module['Path'],module['Version'])]=module
    # Unused optional build-tag graphs can be absent from the cache. -e keeps
    # their public metadata separate; the actual selected dependency graph above
    # must resolve completely, and the resulting source kit is rebuilt offline.
    graph=list(objects(run([go,'list','-m','-e','-json','all'])));cache=Path(run([go,'env','GOMODCACHE']).strip())/'cache/download';inputs={}
    for path,version in modules:
        data=json.loads(run([go,'mod','download','-json',path+'@'+version]))
        for key in ('Zip','GoMod','Info'):
            item=Path(data[key]);inputs[item.relative_to(cache).as_posix()]=item
    for module in graph:
        module=module.get('Replace',module)
        if module.get('GoMod'):
            item=Path(module['GoMod'])
            try:relative=item.relative_to(cache).as_posix()
            except ValueError:continue
            if item.is_file():inputs[relative]=item
    prefix='nextgen-engine-corresponding-source';a.output.parent.mkdir(parents=True,exist_ok=True)
    with tarfile.open(a.output,'w:gz') as archive:
        def add(name,data,mode=0o644):
            info=tarfile.TarInfo(prefix+'/'+name);info.size=len(data);info.mode=mode;info.mtime=0;archive.addfile(info,io.BytesIO(data))
        for name in ('source/.git/refs','source/.git/objects'):
            info=tarfile.TarInfo(prefix+'/'+name);info.type=tarfile.DIRTYPE;info.mode=0o755;info.mtime=0;archive.addfile(info)
        tracked=run(['git','ls-files','-s','-z'])
        gitlinks=[]
        for record in tracked.split('\0'):
            if not record:continue
            metadata,name=record.split('\t',1);item=source/name
            if metadata.startswith('160000'):gitlinks.append(name);continue
            if item.is_symlink():raise ValueError('unexpected tracked symlink')
            add('source/'+name,item.read_bytes(),0o755 if metadata.startswith('100755') else 0o644)
        for item in (source/'.git').rglob('*'):
            relative=item.relative_to(source/'.git').as_posix()
            if item.is_file() and (relative in ('HEAD','index','shallow','packed-refs') or relative.startswith(('objects/','refs/'))):add('source/.git/'+relative,item.read_bytes())
        add('source/.git/config',b'[core]\n repositoryformatversion = 0\n bare = false\n filemode = false\n symlinks = false\n[remote "origin"]\n url = https://github.com/SagerNet/sing-box.git\n')
        for name,item in sorted(inputs.items()):add('module-cache/'+name,item.read_bytes())
        build='''#!/bin/sh
set -eu
ngt_source_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOMAXPROCS=2
export GOPROXY="file://$ngt_source_root/module-cache"
export GOMODCACHE="$ngt_source_root/build-module-cache"
cd "$ngt_source_root/source"
go version
go build -p 2 -trimpath -tags with_quic,with_utls -ldflags=-checklinkname=0 -o "$ngt_source_root/sing-box" ./cmd/sing-box
sha256sum "$ngt_source_root/sing-box"
'''
        add('build-offline.sh',build.encode(),0o755)
        manifest=dict(upstream='https://github.com/SagerNet/sing-box.git',commit=COMMIT,go='1.27.4',tags=['with_quic','with_utls'],expected_binary_sha256=ENGINE_SHA,used_modules=len(modules),proxy_files=len(inputs),unbuilt_client_submodules=gitlinks,note='Linux minimal engine source; separate unbuilt mobile clients are not included. Includes public upstream test fixtures; never use their keys for deployment. Go SDK 1.27.4 and Git are separate prerequisites. All used module source zips are verified against the supplied go.sum during building; checksum verification is not disabled.')
        add('BUILD-MANIFEST.json',json.dumps(manifest,indent=2).encode())
    print(json.dumps(dict(output=str(a.output),sha256=hashlib.sha256(a.output.read_bytes()).hexdigest(),used_modules=len(modules),proxy_files=len(inputs))))

if __name__=='__main__':main()
