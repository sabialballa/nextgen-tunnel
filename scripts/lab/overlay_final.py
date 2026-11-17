"""Final data-plane, underlay and unchanged-main-state checks."""
import argparse,hashlib,json,pathlib,signal,subprocess,time
from overlay_field import baseline,D
def main():
 p=argparse.ArgumentParser();p.add_argument('--node',choices=['iran','turkey'],required=True);a=p.parse_args();other=2 if a.node=='iran' else 1
 report=dict(reboot_tested=False,checks={})
 default=json.loads(subprocess.check_output(['ip','-j','route','show','default'],text=True));dev=default[0]['dev']
 capture=D/'public-overlay.pcap'
 assert not capture.exists()
 process=subprocess.Popen(['tcpdump','-i',dev,'-nn','-s','96','-w',str(capture),'ip proto 47 or udp port 4789 or udp port 51850 or udp port 51860'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
 time.sleep(1)
 try:
  for kind,peer,size in [('gre',f'10.78.250.{other}',1172),('vxlan',f'10.78.251.{other}',1172),('main4',f'10.77.240.{other}',1152),('main6',f'fd77:240::{other}',1152)]:
   out=subprocess.run(['ip','netns','exec','ngt-site-main','ping','-n','-c','3','-W','2','-M','do','-s',str(size),peer],capture_output=True,text=True,timeout=15)
   report['checks'][kind]=dict(success=out.returncode==0,payload_bytes=size)
 finally:
  process.send_signal(signal.SIGINT);_,err=process.communicate(timeout=10)
 assert process.returncode==0
 raw=capture.read_bytes();assert raw[:4] in [b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4']
 report['public_gre_vxlan_wg_packets_observed']=0 if len(raw)==24 else 'nonzero'
 report['public_capture_sha256']=hashlib.sha256(raw).hexdigest();report['capture_log']=err
 report['main_unchanged']=baseline()==json.loads((D/'before.json').read_text())
 units=['nextgen-engine.service','nextgen-site.service','nextgen-site-watchdog.timer','nextgen-overlay-ngo-gre.service','nextgen-overlay-ngo-vxlan.service']
 report['units']={u:dict(active=subprocess.run(['systemctl','is-active','--quiet',u]).returncode==0,enabled=subprocess.run(['systemctl','is-enabled','--quiet',u]).returncode==0) for u in units}
 report['success']=report['main_unchanged'] and all(v['success'] for v in report['checks'].values()) and all(v['active'] and v['enabled'] for v in report['units'].values()) and report['public_gre_vxlan_wg_packets_observed']==0
 report['timestamp']=time.time();(D/'final.json').write_text(json.dumps(report));print(json.dumps(report))
if __name__=='__main__':main()
