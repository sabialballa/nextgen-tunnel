"""Real pinned release download/extraction/version checks in a disposable cache."""
import argparse,json,pathlib,subprocess,sys,tempfile
from unittest import mock
ROOT=pathlib.Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT))
from scripts.menu import download_bundle,digest,CORE_SHA,ENGINE_SHA
def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path,required=True);a=p.parse_args()
    with tempfile.TemporaryDirectory(prefix='nextgen-menu-acceptance-') as directory:
        cache=pathlib.Path(directory);runtime=download_bundle(cache)
        assert digest(runtime/'bin/nextgen-tunnel')==CORE_SHA and digest(runtime/'bin/sing-box')==ENGINE_SHA
        version=subprocess.check_output([str(runtime/'bin/nextgen-tunnel'),'version'],text=True,timeout=10).strip();assert version=='0.3.0-rc3'
        with mock.patch('urllib.request.urlopen',side_effect=AssertionError('cache unexpectedly downloaded again')):assert download_bundle(cache)==runtime
        report=dict(success=True,published_release_downloaded=True,archive_and_manifest_verified=True,core_sha256=CORE_SHA,engine_sha256=ENGINE_SHA,core_version=version,cache_reuse_without_network=True,services_installed=False)
    report['disposable_cache_removed']=not cache.exists();a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report))
if __name__=='__main__':main()
