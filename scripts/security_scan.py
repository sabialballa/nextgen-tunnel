#!/usr/bin/env python3
"""Use the official Go OSV source snapshot when the hosted endpoint is unavailable.

This does not disable verification or suppress advisories. The full official
flat OSV directory is passed to govulncheck's supported local database client.
"""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--go',default='go');p.add_argument('--scanner',type=Path,help='prebuilt govulncheck from verified v1.9.0 source');p.add_argument('--database-repo',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--binary',type=Path);a=p.parse_args()
    repo=a.database_repo.resolve();db=repo/'data/osv'
    if not db.is_dir() or not list(db.glob('GO-*.json')):p.error('official vulndb data/osv checkout required')
    commit=subprocess.check_output(['git','-C',str(repo),'rev-parse','HEAD'],text=True).strip()
    remote=subprocess.check_output(['git','-C',str(repo),'remote','get-url','origin'],text=True).strip()
    if remote not in ('https://github.com/golang/vulndb.git','https://go.googlesource.com/vulndb'):p.error('database must come from an official upstream')
    subprocess.run(['git','-C',str(repo),'diff','--exit-code','HEAD','--','data/osv'],check=True,capture_output=True)
    command=[a.go,'run','golang.org/x/vuln/cmd/govulncheck@v1.9.0','-db',db.as_uri(),'-show','verbose']
    if a.scanner:command=[str(a.scanner.resolve()),'-db',db.as_uri(),'-show','verbose']
    command+=['-mode=binary',str(a.binary)] if a.binary else ['./...']
    result=subprocess.run(command,capture_output=True,text=True,timeout=300)
    report=dict(timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),database_remote=remote,database_commit=commit,osv_entries=len(list(db.glob('GO-*.json'))),scanner='golang.org/x/vuln/cmd/govulncheck@v1.9.0',mode='binary' if a.binary else 'source',returncode=result.returncode,stdout=result.stdout,stderr=result.stderr,security_audit=False)
    if a.binary:report['binary_sha256']=hashlib.sha256(a.binary.read_bytes()).hexdigest()
    if a.scanner:report['scanner_binary_sha256']=hashlib.sha256(a.scanner.read_bytes()).hexdigest()
    a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(report,indent=2))
    print(result.stdout);print(result.stderr,file=sys.stderr);raise SystemExit(result.returncode)
if __name__=='__main__':main()
