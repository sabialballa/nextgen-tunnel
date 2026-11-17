#!/usr/bin/env python3
"""Publish measured field metrics without node addresses; retain raw hashes."""
import argparse
import hashlib
import json
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--input',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    names=['iran-direct.json','iran-native.json','iran-hy2.json','iran-reality.json','iran-obfs.json','iran-gecko-retry.json','iran-direct-final.json','iran-native-final.json','iran-udp-sizes.json','iran-site-bidirectional.json','turkey-site-bidirectional.json','iran-site-obfs.json','iran-site-gecko.json','iran-site-wg-direct.json','turkey-site-reverse-direct.json']
    names+=['turkey-reverse-direct.json','turkey-reverse-reality.json','turkey-reverse-low.json','iran-site-reverse-reality.json','turkey-site-reverse-reality.json','iran-site-load.json','iran-site-low.json','iran-site-soak.json','turkey-site-recovery.json']
    records=[]
    for name in names:
        path=a.input/name
        if not path.exists():raise ValueError('missing raw result '+name)
        raw=path.read_bytes();data=json.loads(raw)
        if isinstance(data,dict):
            for check in data.get('checks',[]):
                peer=check.pop('peer',None)
                if peer:check['family']='ipv6' if ':' in peer else 'ipv4'
        records.append(dict(source=name,sha256=hashlib.sha256(raw).hexdigest(),result=data))
    indexed={v['source']:v['result'] for v in records}
    reverse_passed=all(indexed[n]['success'] for n in ('iran-site-reverse-reality.json','turkey-site-reverse-reality.json','iran-site-soak.json','turkey-site-recovery.json'))
    report=dict(schema_version=1,scope='two authorized Ubuntu 24.04 VPSs, both initiation directions, bounded bidirectional echo',management_iran_vpn_bypassed=True,reverse_site_checks_passed=reverse_passed,production_acceptance=False,dpi_bypass_proven=False,maximum_throughput_measured=False,notes=['Initiating the outer connection in Iran failed sustained tests; the exact cause is not established.','Initiating REALITY in Turkey carried bidirectional WireGuard site TCP/UDP and IPv4/IPv6 successfully.','Direct reverse TCP measurements completed, but direct UDP still lost 99.8336 percent in that run.','Benchmark success denotes completed measurement, not an acceptable loss/latency budget or production acceptance.','Site under 5 Mbps offered TCP plus 1 Mbps UDP had 2.7904 percent UDP loss; at 0.5/0.1 Mbps it received all 1563 UDP echoes. These are different load conditions.','The 2000-round dual-stack site run lasted about 254 seconds and is not a multi-hour stability test.','The real carrier stop/replacement test preserved one established inner TCP connection.','Early benchmarks stopped on first TCP error; final direct/native runs attempt UDP independently.','Gecko retry is the actual running-carrier measurement; the earlier stopped-service attempt is excluded.','Reverse WireGuard baseline changed only the test peer endpoint temporarily; host routes stayed unchanged.'],measurements=records)
    a.output.write_text(json.dumps(report,indent=2));print(str(a.output))

if __name__=='__main__':main()
