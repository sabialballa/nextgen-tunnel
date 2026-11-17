#!/usr/bin/env python3
"""Sanitize paired reports and correlate authenticated UDP MACs in header captures."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import struct
import re

def packets(path):
    data=path.read_bytes();magic=data[:4]
    endian='<' if magic in (b'\xd4\xc3\xb2\xa1',b'\x4d\x3c\xb2\xa1') else '>'
    if magic not in (b'\xd4\xc3\xb2\xa1',b'\xa1\xb2\xc3\xd4',b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d') or len(data)<24:raise ValueError('unsupported capture')
    if struct.unpack_from(endian+'I',data,20)[0]!=1:raise ValueError('Ethernet capture required')
    scale=1e9 if magic in (b'\x4d\x3c\xb2\xa1',b'\xa1\xb2\x3c\x4d') else 1e6
    offset=24;result=[];times=[]
    while offset<len(data):
        if offset+16>len(data):raise ValueError('truncated capture record')
        sec,part,size,wire=struct.unpack_from(endian+'IIII',data,offset);offset+=16
        if size>65536 or offset+size>len(data):raise ValueError('invalid capture record length')
        packet=data[offset:offset+size];offset+=size;timestamp=sec+part/scale;times.append(timestamp)
        if len(packet)<42 or packet[12:14]!=b'\x08\x00' or packet[23]!=17:continue
        ip=14;ihl=(packet[ip]&15)*4
        if ihl<20 or len(packet)<ip+ihl+40 or struct.unpack_from('!H',packet,ip+6)[0]&8191:continue
        udp=ip+ihl;source,destination,length=struct.unpack_from('!HHH',packet,udp)
        if length!=168:continue
        mac=packet[udp+8:udp+40].hex()
        result.append(dict(timestamp=timestamp,source=socket.inet_ntoa(packet[ip+12:ip+16]),destination=socket.inet_ntoa(packet[ip+16:ip+20]),sport=source,dport=destination,mac=mac))
    if not times:raise ValueError('empty capture')
    return result,min(times),max(times)

def main():
    p=argparse.ArgumentParser();p.add_argument('--private-directory',type=Path,required=True);p.add_argument('--iran-ip',required=True);p.add_argument('--turkey-ip',required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    report=dict(version='0.3.0-rc2',scope='Simultaneous authenticated direct IPv4 and tunneled IPv4/IPv6 TCP/UDP, in both directions',nodes={},captures={})
    for node in ('iran','turkey'):
        report['nodes'][node]={}
        for phase in ('baseline','retake'):
            path=a.private_directory/(node+'-compare-'+phase+'.json')
            if not path.exists():continue
            raw=path.read_bytes();r=json.loads(raw);safe={k:r[k] for k in ('started_wall_time','finished_wall_time','elapsed_seconds','seconds_requested','complete','driver_sha256') if k in r};safe['paths']={}
            for name,path_data in r['paths'].items():
                flows={}
                for protocol,v in path_data['flows'].items():
                    flows[protocol]={k:value for k,value in v.items() if k!='events'};flows[protocol]['event_count']=len(v['events']);flows[protocol]['event_timestamps']=[e['timestamp'] for e in v['events'][:50]];flows[protocol]['loss_percent']=100*(v['sent']-v['received'])/v['sent'] if v['sent'] else None
                safe['paths'][name]=dict(complete=path_data['complete'],flows=flows)
            samples=r.get('samples',[]);safe['engine_pid_stable']=bool(samples) and len({s['engine'] for s in samples})==1 and all('ActiveState=active' in s['engine'] and 'MainPID=0\n' not in s['engine'] for s in samples);safe['raw_sha256']=hashlib.sha256(raw).hexdigest();report['nodes'][node][phase]=safe
    capture_paths={n:a.private_directory/(n+'-compare-baseline-headers.pcap') for n in ('iran','turkey')}
    if all(p.exists() for p in capture_paths.values()):
        captures={n:packets(p) for n,p in capture_paths.items()};start=max(v[1] for v in captures.values())+2;end=min(v[2] for v in captures.values())-2
        report['capture_common_window_seconds']=max(0,end-start)
        for node,peer,ip in (('iran','turkey',a.iran_ip),('turkey','iran',a.turkey_ip)):
            rows=captures[node][0];other=captures[peer][0];sent={r['mac'] for r in rows if r['source']==ip and r['sport']==29401 and start<=r['timestamp']<=end};received={r['mac'] for r in other if r['source']==ip and r['sport']==29401};requests={r['mac'] for r in rows if r['destination']==ip and r['dport']==29401 and start<=r['timestamp']<=end}
            report['captures'][node]=dict(raw_sha256=hashlib.sha256(capture_paths[node].read_bytes()).hexdigest(),unique_requests_seen_at_server_nic=len(requests),unique_replies_sent_by_server_nic=len(sent),matching_replies_seen_at_peer_nic=len(sent&received),replies_not_seen_at_peer_nic=len(sent-received))
            log=a.private_directory/(node+'-compare-capture-log.txt')
            if log.exists():report['captures'][node].update(capture_log_sha256=hashlib.sha256(log.read_bytes()).hexdigest(),kernel_capture_drop_counts=[int(x) for x in re.findall(r'(\d+) packets dropped by kernel',log.read_text())])
    fault=a.private_directory/'turkey-compare-fault.json'
    if fault.exists():report['controlled_fault']=json.loads(fault.read_text())
    report['half_hour_complete']=all(report['nodes'][n].get('retake',{}).get('complete') and report['nodes'][n]['retake'].get('elapsed_seconds',0)>=1800 for n in ('iran','turkey'))
    def accepts(r):
        f=r['paths']['site']['flows']
        return r['engine_pid_stable'] and len(f)==4 and all(v['received']>0 and v['corrupted']==0 and v['connect_errors']==0 and (v['timeouts']==0 and v['reconnects']==0 if k.endswith('tcp') else v['loss_percent']<=.5 and v['max_burst']<=3) for k,v in f.items())
    report['half_hour_site_acceptance']=report['half_hour_complete'] and all(accepts(report['nodes'][n]['retake']) for n in ('iran','turkey'))
    fault_data=report.get('controlled_fault',{});report['controlled_fault_without_site_timeouts']=False
    if fault_data.get('completed') and fault_data.get('firewall_restored') and all('retake' in report['nodes'][n] for n in ('iran','turkey')):
        flows=[v for n in ('iran','turkey') for v in report['nodes'][n]['retake']['paths']['site']['flows'].values()]
        report['controlled_fault_without_site_timeouts']=all(v['event_count']<=50 and not any(fault_data['started_wall_time']-1<=t<=fault_data['finished_wall_time']+3 for t in v['event_timestamps']) for v in flows)
    report['production_certified']=False
    a.output.write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(dict(half_hour_complete=report['half_hour_complete'],half_hour_site_acceptance=report['half_hour_site_acceptance'],captures=report['captures'])))

if __name__=='__main__':main()
