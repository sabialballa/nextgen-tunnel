"""Build the optional Python overlay add-on without modifying rc3 binaries."""
import gzip,hashlib,io,json,pathlib,tarfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
def main():
 name='nextgen-overlays-0.2.0';files=['scripts/overlay.py','scripts/overlay_service.py','docs/overlays.md','LICENSE','docs/evidence/overlay-field.json','docs/evidence/overlay-hour-comparison.json']+[str(p.relative_to(ROOT)).replace('\\','/') for p in sorted((ROOT/'configs/examples/overlays').glob('*.json'))]
 payload={f:(ROOT/f).read_bytes() for f in files};manifest={f:hashlib.sha256(data).hexdigest() for f,data in payload.items()};payload['MANIFEST.json']=(json.dumps(manifest,indent=2)+'\n').encode()
 target=ROOT/'dist'/(name+'.tar.gz');assert not target.exists(),'immutable add-on already exists'
 with target.open('xb') as raw,gzip.GzipFile(fileobj=raw,mode='wb',mtime=0) as zipped,tarfile.open(fileobj=zipped,mode='w') as archive:
  for path,data in sorted(payload.items()):
   info=tarfile.TarInfo(name+'/'+path);info.size=len(data);info.mode=0o644;info.mtime=0;archive.addfile(info,io.BytesIO(data))
 with tarfile.open(target) as archive:
  assert len(archive.getmembers())==len(payload)
  for member in archive.getmembers():assert member.isfile() and archive.extractfile(member).read()==payload[member.name[len(name)+1:]]
 sha=hashlib.sha256(target.read_bytes()).hexdigest();(target.with_suffix('').with_suffix('.sha256')).write_text(sha+'  '+target.name+'\n',encoding='ascii')
 print(json.dumps(dict(archive=target.name,sha256=sha,members=len(payload),verified=True)))
if __name__=='__main__':main()
