#!/usr/bin/env python3
"""Console-to-console pairing. No inter-server management connection or SSH.

Invitation codes contain client authentication credentials, not private keys.
Copy them through a trusted channel. Encoding/checksum is not encryption or
sender authentication. Replies authenticate possession of the invitation secret.
"""
import base64,getpass,hashlib,hmac,ipaddress,json,os,platform,re,secrets,subprocess,sys,time,uuid
from pathlib import Path
if __package__:
    from .easy_node import Node,STATE,write_json,public_key,client_export
    from .easy_install import dependencies
else:
    from easy_node import Node,STATE,write_json,public_key,client_export
    from easy_install import dependencies

TICKET=STATE/'console-pair.json'
MAX_CODE=4096
LIFETIME=24*60*60

def canonical(data):return json.dumps(data,sort_keys=True,separators=(',',':')).encode('ascii')

def address(value):
    value=str(ipaddress.IPv4Address(value));ip=ipaddress.ip_address(value)
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast or ip.is_link_local or value=='255.255.255.255':raise ValueError('A reachable unicast IPv4 address is required.')
    return value

def encode(kind,data):
    raw=canonical(data)
    return 'NGT1-'+kind+'-'+base64.urlsafe_b64encode(raw).decode().rstrip('=')+'-'+hashlib.sha256(raw).hexdigest()[:16]

def decode(kind,code):
    if not isinstance(code,str) or len(code)>MAX_CODE:raise ValueError('Invalid or oversized pairing code.')
    prefix='NGT1-'+kind+'-'
    if not code.startswith(prefix):raise ValueError('Wrong code type; copy the complete '+prefix+' code.')
    try:
        encoded,check=code[len(prefix):].rsplit('-',1)
        if not re.fullmatch('[A-Za-z0-9_-]+',encoded):raise ValueError()
        raw=base64.b64decode(encoded+'='*((-len(encoded))%4),altchars=b'-_',validate=True)
        if not hmac.compare_digest(hashlib.sha256(raw).hexdigest()[:16],check):raise ValueError()
        data=json.loads(raw)
        if not isinstance(data,dict) or canonical(data)!=raw:raise ValueError()
        return data
    except (ValueError,TypeError,UnicodeError,RecursionError):raise ValueError('Pairing code is damaged or invalid.') from None

def invitation(code,now=None):
    d=decode('I',code);now=time.time() if now is None else now
    if set(d)!={'pair','listener','peer','expires','secret','public_key','client'}:raise ValueError('Unexpected invitation fields.')
    if not isinstance(d['pair'],str) or not re.fullmatch('[0-9a-f]{32}',d['pair']):raise ValueError('Invalid pairing ID.')
    if type(d['expires']) is not int or not now<d['expires']<=now+LIFETIME+300:raise ValueError('Invitation expired or clock incorrect; check both server clocks.')
    if not isinstance(d['secret'],str) or not re.fullmatch('[0-9a-f]{64}',d['secret']):raise ValueError('Invalid pairing secret.')
    if not isinstance(d['listener'],str) or not isinstance(d['peer'],str):raise ValueError('Invalid server address.')
    if not isinstance(d['client'],dict) or not all(isinstance(v,str) for v in d['client'].values()):raise ValueError('Invalid client identity.')
    if address(d['listener'])==address(d['peer']):raise ValueError('The two server IPs must differ.')
    public_key(d['public_key']);client_export(d['client'],d['listener'])
    return d

def offer_hash(offer):return hashlib.sha256(canonical(offer)).hexdigest()

def reply(offer,key):
    public_key(key);d=dict(pair=offer['pair'],offer_hash=offer_hash(offer),public_key=key)
    d['mac']=hmac.new(bytes.fromhex(offer['secret']),canonical(d),hashlib.sha256).hexdigest()
    return encode('R',d)

def accept_reply(offer,code):
    d=decode('R',code)
    if set(d)!={'pair','offer_hash','public_key','mac'}:raise ValueError('Unexpected reply fields.')
    if d['pair']!=offer['pair'] or d['offer_hash']!=offer_hash(offer):raise ValueError('Reply belongs to a different invitation.')
    mac=d.pop('mac');expected=hmac.new(bytes.fromhex(offer['secret']),canonical(d),hashlib.sha256).hexdigest()
    if not isinstance(mac,str) or not hmac.compare_digest(mac,expected):raise ValueError('Reply authentication failed.')
    return public_key(d['public_key'])

def read_ticket():
    if TICKET.is_symlink():raise ValueError('Unsafe console pairing state.')
    return json.loads(TICKET.read_text()) if TICKET.exists() else None

def check_identity(node,ticket):
    s=node.state();o=ticket['offer']
    if not s or s['pair_id']!=o['pair'] or s['role']!=ticket['role'] or s['listener']!=o['listener'] or s['peer']!=(o['peer'] if ticket['role']=='listener' else o['listener']):raise ValueError('Console pairing state does not match the prepared node.')
    node.verify_files(s)

def listener_offer(node,own,peer):
    own,peer=address(own),address(peer)
    if own==peer:raise ValueError('The two server IPs must differ.')
    ticket=read_ticket()
    if ticket:
        if ticket['role']!='listener' or ticket['offer']['listener']!=own or ticket['offer']['peer']!=peer:raise ValueError('Existing console pair has a different role or IP; keys were preserved.')
        check_identity(node,ticket);return ticket
    s=node.state()
    # Persist the random pairing ID before preparation so interrupted preparation
    # can resume without silently generating a new identity or rotating keys.
    pending=STATE/'console-pending.json'
    if pending.is_symlink():raise ValueError('Unsafe pending state.')
    if pending.exists():
        draft=json.loads(pending.read_text())
        if draft['listener']!=own or draft['peer']!=peer:raise ValueError('A different console pair is pending; keys were preserved.')
    else:
        if s:raise ValueError('Existing installation/preparation preserved; console pairing cannot adopt it.')
        node.metadata(dict(peer=peer))
        draft=dict(pair=uuid.uuid4().hex,listener=own,peer=peer,secret=secrets.token_hex(32));write_json(pending,draft)
    exported=node.prepare(dict(role='listener',peer=peer,listener=own,pair_id=draft['pair']))
    offer=dict(draft,expires=int(time.time())+LIFETIME,public_key=exported['public_key'],client=exported['client'])
    ticket=dict(role='listener',offer=offer);write_json(TICKET,ticket);return ticket

def join(node,code):
    offer=invitation(code);ticket=read_ticket()
    if ticket:
        stable=lambda o:{k:v for k,v in o.items() if k not in ('secret','expires')}
        if ticket['role']!='initiator' or stable(ticket['offer'])!=stable(offer):raise ValueError('This server already has a different console pair; keys were preserved.')
    elif node.state():
        s=node.state()
        if s['pair_id']!=offer['pair'] or s['role']!='initiator' or s['listener']!=offer['listener'] or s['peer']!=offer['listener']:raise ValueError('Existing installation/preparation preserved; console pairing cannot adopt it.')
    else:node.metadata(dict(peer=offer['listener']))
    node.prepare(dict(role='initiator',peer=offer['listener'],listener=offer['listener'],pair_id=offer['pair']))
    ticket=dict(role='initiator',offer=offer);write_json(TICKET,ticket)
    node.configure(dict(peer_public_key=offer['public_key'],client=offer['client']))
    return ticket

def install_local(node):
    attempt=uuid.uuid4().hex
    try:
        node.install(dict(attempt=attempt));node.overlays(dict(attempt=attempt))
    except BaseException:
        try:node.rollback(dict(attempt=attempt))
        except (ValueError,OSError,KeyError,subprocess.SubprocessError):print('Local rollback was not confirmed; check installation status.',file=sys.stderr)
        raise
    # A local install must survive the peer still waiting at its own console.
    # Connectivity failure is pending status, not grounds to remove this side.
    result=node.probe(dict(overlays=True))
    if result['healthy']:print('This server is installed; site and all overlay connectivity checks passed.')
    else:print('This server is installed. Peer connectivity is not yet confirmed. Finish pairing on the other server, then run this option again.')
    return result

def run(ask=input,read_code=None):
    if sys.platform!='linux' or os.geteuid()!=0 or platform.machine()!='x86_64':raise ValueError('Console pairing requires Linux x64 and root.')
    if read_code is None:read_code=getpass.getpass
    print('\nInstall this server without inter-server SSH. Run this option on both servers.\nStart on Iran/listener. Copy the invitation to Outside Iran/initiator, then copy its reply back.\nCodes contain client access credentials. Copy through a trusted channel; do not post or share them.')
    role={'1':'listener','2':'initiator'}.get(ask('Local role: 1=Iran / listener, 2=Outside Iran / initiator: ').strip())
    if not role:raise ValueError('Invalid role.')
    with Node() as node:
        ticket=read_ticket()
        if ticket and ticket['role']!=role:raise ValueError('Existing console pair has a different role; keys were preserved.')
        if ticket:check_identity(node,ticket)
        dependencies(require_ssh=False)
        if role=='listener':
            if not ticket:
                own=ask('This listener\'s reachable IPv4: ').strip();peer=ask('Initiator IPv4: ').strip();ticket=listener_offer(node,own,peer)
            if not node.state().get('configuration_signature'):
                if ticket['offer']['expires']<=time.time():
                    ticket['offer'].update(secret=secrets.token_hex(32),expires=int(time.time())+LIFETIME)
                    write_json(TICKET,ticket)
                    print('The expired invitation was renewed. Older invitation and reply codes are no longer accepted; paste the new invitation on the initiator.')
                invitation(encode('I',ticket['offer'])) # Reject expired invitation before accepting replies.
                print('\nInvitation code (keep private, valid for 24 hours):\n'+encode('I',ticket['offer']),flush=True)
                code=read_code('Paste the initiator reply code, or press Enter to finish later: ').strip()
                if not code:print('Invitation saved. Run this option again on this server to continue.');return
                key=accept_reply(ticket['offer'],code);node.configure(dict(peer_public_key=key))
        else:
            if ticket:
                action=ask('1=Resume/check this pair, 2=Import a renewed invitation [1]: ').strip() or '1'
                if action not in ('1','2'):raise ValueError('Invalid option.')
                if action=='2':ticket=join(node,read_code('Paste the renewed listener invitation (input hidden): ').strip())
            if not ticket:ticket=join(node,read_code('Paste the listener invitation code (input hidden): ').strip())
            else:
                node.configure(dict(peer_public_key=ticket['offer']['public_key'],client=ticket['offer']['client']))
            print('\nReply code: paste this back on the listener console:\n'+reply(ticket['offer'],node.export(node.state())['public_key']),flush=True)
        return install_local(node)

if __name__=='__main__':
    try:run()
    except (ValueError,OSError,KeyError,subprocess.SubprocessError) as exc:print('Console installation failed: '+str(exc),file=sys.stderr);raise SystemExit(1)
