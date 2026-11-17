"""Exercise only new owned overlays, preserving the existing engine and site."""
import hashlib,json,pathlib,subprocess,time
from overlay_field import baseline,D,CODE
def call(args):return subprocess.check_output(args,text=True,timeout=60).strip()
def main():
 result={'checks':{},'reboot_tested':False}
 service=['python3','-B',str(CODE/'overlay_service.py')]
 for kind in ['gre','vxlan']:
  cfg=D/(kind+'.json');c=json.loads(cfg.read_text());unit='nextgen-overlay-'+c['name']+'.service'
  if kind=='gre':
   call(service+['remove','--config',str(cfg),'--apply']);call(service+['install','--config',str(cfg),'--apply'])
  else:call(['systemctl','restart',unit])
  assert call(service+['install','--config',str(cfg),'--apply'])=='unchanged'
  status=json.loads(call(service+['status','--config',str(cfg)]));assert status=={'owned':True,'active':'active','enabled':True}
  original=json.loads(call(['ip','-n',c['namespace'],'-d','-j','link','show',c['name']]))[0]
  bad={**c,'address':c['address'].replace('/30','/31')};q=D/('invalid-'+kind+'.json');q.write_text(json.dumps(bad))
  refused=subprocess.run(['python3','-B',str(CODE/'overlay.py'),'create','--config',str(q),'--apply'],capture_output=True,text=True,timeout=20);assert refused.returncode!=0
  now=json.loads(call(['ip','-n',c['namespace'],'-d','-j','link','show',c['name']]))[0];assert now['ifindex']==original['ifindex'] and now['ifalias']==original['ifalias'];q.unlink()
  result['checks'][kind]=dict(service_status=status,config_mismatch_rejected=True,owned_interface_preserved=True,uninstall_reinstall_tested=kind=='gre',restart_tested=kind=='vxlan')
 assert baseline()==json.loads((D/'before.json').read_text())
 result.update(success=True,main_unchanged=True,timestamp=time.time());(D/'recovery.json').write_text(json.dumps(result));print(json.dumps(result))
if __name__=='__main__':main()
