"""Summarize bounded direct-UDP pcaps without publishing packet identifiers."""
import collections,hashlib,json,pathlib,struct
ROOT=pathlib.Path(__file__).resolve().parents[2]
def read(p):
 raw=p.read_bytes();assert raw[:4]==b'\xd4\xc3\xb2\xa1';assert struct.unpack('<I',raw[20:24])[0]==276
 offset=24;packets=[]
 while offset<len(raw):
  sec,usec,size,original=struct.unpack('<IIII',raw[offset:offset+16]);offset+=16;data=raw[offset:offset+size];offset+=size
  assert data[:2]==b'\x08\x00';ip=data[20:];assert ip[9]==17
  ihl=(ip[0]&15)*4;src,dst,length,checksum=struct.unpack('!HHHH',ip[ihl:ihl+8]);payload=ip[ihl+8:]
  assert length==168 and len(payload)>=48
  packets.append(dict(time=sec+usec/1e6,direction='out' if data[10]==4 else 'in',kind='request' if dst==29401 else 'reply',identity=hashlib.sha256(payload[:48]).hexdigest()))
 return packets
def main():
 nodes={};packets={}
 for node in ['iran','turkey']:
  p=ROOT/'.private/remote-lab'/f'{node}-low-direct.pcap';packets[node]=read(p)
  count=collections.Counter(v['kind']+'_'+v['direction'] for v in packets[node])
  nodes[node]=dict(counts=dict(count),captured=len(packets[node]),first_timestamp=packets[node][0]['time'],last_timestamp=packets[node][-1]['time'],pcap_sha256=hashlib.sha256(p.read_bytes()).hexdigest())
 def ids(node,kind,direction):return {v['identity'] for v in packets[node] if v['kind']==kind and v['direction']==direction}
 matches=dict(turkey_requests_matched_at_iran=len(ids('turkey','request','out') & ids('iran','request','in')),iran_replies_matched_to_received_requests=len(ids('iran','reply','out') & ids('iran','request','in')),iran_replies_matched_at_turkey=len(ids('iran','reply','out') & ids('turkey','reply','in')))
 output=dict(nodes=nodes,payload_prefix_identity_matches=matches,snapshot_bytes=96,capture_seconds_requested=15,observed_kernel_capture_drops_both_nodes=0,limitations=['Short sample only; capture windows differ slightly','Missing packets cannot identify the responsible network device','Direction is Linux cooked v2 packet type; identity uses captured authenticated payload prefix without publishing it'])
 p=ROOT/'docs/evidence/low-load-direct-capture.json';p.write_text(json.dumps(output,indent=2)+'\n',encoding='utf-8');print(json.dumps(output,indent=2))
if __name__=='__main__':main()
