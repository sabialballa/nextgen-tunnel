"""Bounded kernel overlay acceptance on the existing isolated TCP-backed site."""
import argparse,hashlib,json,pathlib,subprocess,time
D=pathlib.Path('/opt/nextgen-stack-stage/overlay-v1');CODE=pathlib.Path('/usr/local/lib/nextgen-overlay');MARKER=pathlib.Path('/var/lib/nextgen-stack-installer/ownership.json')
def call(args,**kwargs):return subprocess.check_output(args,text=True,timeout=90,**kwargs).strip()
def baseline():return dict(marker=hashlib.sha256(MARKER.read_bytes()).hexdigest(),files={p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest() for p in json.loads(MARKER.read_text())['hashes']},routes=call(['ip','-j','route','show']),routes6=call(['ip','-j','-6','route','show']),firewall=call(['nft','list','ruleset']),forwarding=pathlib.Path('/proc/sys/net/ipv4/ip_forward').read_text())
def main():
 p=argparse.ArgumentParser();p.add_argument('action',choices=['prepare','probe','finish']);p.add_argument('--node',choices=['iran','turkey'],required=True);a=p.parse_args();number=1 if a.node=='iran' else 2;other=3-number
 def overlay(action,kind):return call(['python3','-B',str(CODE/'overlay.py'),action,'--config',str(D/(kind+'.json')),'--apply'])
 if a.action=='prepare':
  assert not (D/'before.json').exists();(D/'before.json').write_text(json.dumps(baseline()))
  for kind,subnet in [('gre',250),('vxlan',251)]:
   c=dict(name='ngo-'+kind,namespace='ngt-site-main',kind=kind,local=f'10.77.240.{number}',remote=f'10.77.240.{other}',address=f'10.78.{subnet}.{number}/30',mtu=1200)
   if kind=='vxlan':c.update(vni=10771,port=4789)
   q=D/(kind+'.json');q.write_text(json.dumps(c));q.chmod(0o600);overlay('create',kind);assert overlay('create',kind)=='unchanged'
  cmd=['systemd-run','--quiet','--unit=nextgen-overlay-test-echo','-p','RuntimeMaxSec=600','-p','DynamicUser=yes','-p','MemoryMax=64M','-p','TasksMax=20','-p','NoNewPrivileges=yes','-p','ProtectSystem=strict','-p','ProtectHome=yes','-p','NetworkNamespacePath=/run/netns/ngt-site-main','-p','LoadCredential=secret:'+str(D/'secret'),'python3','-B',str(CODE/'path_compare.py'),'server','--secret','/run/credentials/nextgen-overlay-test-echo.service/secret','--port','21921']
  for subnet in [250,251]:cmd+=['--bind',f'10.78.{subnet}.{number}','--allow',f'10.78.{subnet}.{other}']
  call(cmd);print(json.dumps({'prepared':True}));return
 if a.action=='probe':
  report=dict(started=time.time(),checks={})
  for kind,subnet in [('gre',250),('vxlan',251)]:
   peer=f'10.78.{subnet}.{other}'
   ping=subprocess.run(['ip','netns','exec','ngt-site-main','ping','-n','-c','3','-W','2','-M','do','-s','1172',peer],capture_output=True,text=True,timeout=15)
   command=['ip','netns','exec','ngt-site-main','runuser','-u','nobody','--','python3','-B',str(CODE/'path_compare.py'),'worker','--peer',peer,'--port','21921','--seconds','30','--udp-interval','1','--tcp-interval','2']
   output=call(command,input=(D/'secret').read_bytes().hex()+'\n');raw=[json.loads(v) for v in output.splitlines()];assert raw[-1]['complete']
   report['checks'][kind]=dict(mtu_ping_success=ping.returncode==0,ping=ping.stdout,probe=raw[-1],owned_status=json.loads(overlay('status',kind)))
  report['complete']=True;report['finished']=time.time();(D/'probe.json').write_text(json.dumps(report));print(json.dumps({'complete':True}));return
 if a.action=='finish':
  r=json.loads((D/'probe.json').read_text());assert r['complete']
  call(['systemctl','stop','nextgen-overlay-test-echo.service'])
  # Recovery by removing and recreating only each owned overlay, then preserve
  # configs and the production helper for optional managed activation.
  recovery={}
  for kind in ['gre','vxlan']:
   overlay('remove',kind);overlay('create',kind);recovery[kind]=json.loads(overlay('status',kind))['present']
  assert baseline()==json.loads((D/'before.json').read_text())
  (D/'secret').unlink();(CODE/'path_compare.py').unlink()
  result=dict(success=True,main_unchanged=True,temporary_echo_stopped=True,test_credentials_removed=True,overlay_recreate_success=recovery,timestamp=time.time())
  (D/'finish.json').write_text(json.dumps(result));print(json.dumps(result))
if __name__=='__main__':main()
