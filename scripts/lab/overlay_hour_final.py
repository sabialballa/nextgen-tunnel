"""Final MTU/native-public-packet checks after both authorized real reboots."""
import argparse,hashlib,json,pathlib,signal,subprocess,sys,time
sys.path.insert(0,'/usr/local/lib/nextgen-overlay-hour')
from overlay_hour import baseline,D
def main():
 p=argparse.ArgumentParser();p.add_argument('--node',choices=['iran','turkey'],required=True);a=p.parse_args();other=2 if a.node=='iran' else 1
 default=json.loads(subprocess.check_output(['ip','-j','route','show','default'],text=True));pcap=D/'public-after-reboots.pcap';assert not pcap.exists()
 process=subprocess.Popen(['tcpdump','-i',default[0]['dev'],'-nn','-s','96','-w',str(pcap),'ip proto 4 or ip proto 47 or udp port 4789 or udp port 51850 or udp port 51860'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True);time.sleep(1)
 report=dict(checks={})
 try:
  for kind,peer,size in [('gre',f'10.78.250.{other}',1172),('vxlan',f'10.78.251.{other}',1172),('ipip',f'10.78.252.{other}',1172),('base4',f'10.77.240.{other}',1152),('base6',f'fd77:240::{other}',1152)]:
   result=subprocess.run(['ip','netns','exec','ngt-site-main','ping','-n','-c','3','-W','2','-M','do','-s',str(size),peer],capture_output=True,text=True,timeout=15);report['checks'][kind]=dict(success=result.returncode==0,payload_bytes=size)
 finally:process.send_signal(signal.SIGINT);_,err=process.communicate(timeout=10)
 assert process.returncode==0;raw=pcap.read_bytes()
 report.update(native_public_overlay_packets=0 if len(raw)==24 else 'nonzero',capture_sha256=hashlib.sha256(raw).hexdigest(),capture_kernel_drops=0 if '0 packets dropped by kernel' in err else 'unknown',main_and_overlay_files_host_state_unchanged=baseline()==json.loads((D/'before.json').read_text()),timestamp=time.time())
 report['success']=all(v['success'] for v in report['checks'].values()) and report['native_public_overlay_packets']==0 and report['capture_kernel_drops']==0 and report['main_and_overlay_files_host_state_unchanged']
 (D/'final.json').write_text(json.dumps(report));print(json.dumps(report))
if __name__=='__main__':main()
