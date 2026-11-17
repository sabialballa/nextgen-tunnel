"""Publish sanitized optional-overlay acceptance evidence."""
import hashlib,json,pathlib
ROOT=pathlib.Path(__file__).resolve().parents[2]
def main():
 out=dict(nodes={},public_carrier='REALITY/smux over TCP443',mtu=1200,ipv4_only=True,production_certified=False,reboot_tested=False,github_published=False,limitations=['Thirty seconds per overlay per node; tests were sequential','No demonstrated stability improvement or repaired UDP deadlines','No physical LAN bridge, host routes, NAT or Internet egress configured','Boot ordering configured but no server reboot performed'])
 for node in ['iran','turkey']:
  data={};hashes={}
  for kind in ['probe','finish','recovery','final']:
   p=ROOT/'.private/remote-lab'/f'{node}-overlay-{kind}.json';data[kind]=json.loads(p.read_text());hashes[kind]=hashlib.sha256(p.read_bytes()).hexdigest()
  assert data['probe']['complete'] and all(data[k]['success'] for k in ['finish','recovery','final'])
  checks={}
  for kind,c in data['probe']['checks'].items():
   flows={n:{k:v[k] for k in ['sent','received','timeouts','corrupted','late','max_burst','rtt_max_ms']} for n,v in c['probe']['flows'].items()}
   checks[kind]=dict(mtu_ping_success=c['mtu_ping_success'],probe_seconds_requested=30,flows=flows)
  final={k:v for k,v in data['final'].items() if k!='capture_log'}
  final['public_capture_kernel_drops']=0 if '0 packets dropped by kernel' in data['final']['capture_log'] else 'unknown'
  out['nodes'][node]=dict(checks=checks,cleanup=data['finish'],recovery=data['recovery'],final=final,raw_sha256=hashes)
 out['connectivity_acceptance']=all(v['mtu_ping_success'] and all(s['received']>0 and s['corrupted']==0 for s in v['flows'].values()) for n in out['nodes'].values() for v in n['checks'].values())
 out['udp_deadline_acceptance']=all(s['timeouts']==0 for n in out['nodes'].values() for v in n['checks'].values() for s in v['flows'].values())
 (ROOT/'docs/evidence/overlay-field.json').write_text(json.dumps(out,indent=2)+'\n',encoding='utf-8');print(json.dumps({'connectivity':out['connectivity_acceptance'],'udp_deadlines':out['udp_deadline_acceptance']}))
if __name__=='__main__':main()
