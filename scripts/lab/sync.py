#!/usr/bin/env python3
"""Transfer only public source/build inputs to the pinned project-owned VM."""
import os
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from scripts.package import sources,audit
from scripts.lab.vm import ssh_args

def main():
    paths=sources();audit(paths);lab=ROOT/'.private/linux-lab'
    with tarfile.open(lab/'source.tar.gz','w:gz') as t:
        for p in paths:t.add(p,arcname=str(p.relative_to(ROOT)),recursive=False)
        t.add(ROOT/'dist/nextgen-tunnel-linux-amd64',arcname='bin/nextgen-tunnel',recursive=False)
    cache=Path.home()/'go/pkg/mod/cache/download'
    prefixes=('github.com/quic-go','github.com/stretchr','github.com/davecgh','github.com/pmezard','github.com/jordanlewis','go.uber.org/mock','golang.org/x/','gopkg.in/','go.yaml.in/','sumdb/')
    with tarfile.open(lab/'modules.tar.gz','w:gz') as t:
        for p in cache.rglob('*'):
            rel=p.relative_to(cache).as_posix()
            if p.is_file() and rel.startswith(prefixes) and not p.name.endswith(('.lock','.tmp','.partial')):
                t.add(p,arcname='go/pkg/mod/cache/download/'+rel,recursive=False)
    args=ssh_args('debian12')
    for file,target in ((lab/'source.tar.gz','/home/lab/source.tar.gz'),(lab/'modules.tar.gz','/home/lab/modules.tar.gz')):
        with file.open('rb') as f:subprocess.run(args+[f'cat > {target}'],stdin=f,check=True)
    subprocess.run(args+['mkdir -p /home/lab/project && tar -xzf /home/lab/source.tar.gz -C /home/lab/project && tar -xzf /home/lab/modules.tar.gz -C /home/lab && chmod +x /home/lab/project/bin/nextgen-tunnel'],check=True)
if __name__=='__main__':main()
