#!/usr/bin/env python3
"""Prepare isolated field test configs; never print or distribute server secrets."""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import ssl
import subprocess

def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);p.add_argument('--server-ip',required=True);p.add_argument('--peer-ip',required=True);a=p.parse_args();d=a.directory.resolve()
    socket.inet_aton(a.server_ip);socket.inet_aton(a.peer_ip)
    if not d.name.startswith('nextgen-field-'):p.error('dedicated field directory required')
    binary=d/'nextgen-tunnel'
    # Verify a real TLS1.3 handshake at the REALITY camouflage destination.
    name='www.microsoft.com';ctx=ssl.create_default_context();ctx.minimum_version=ssl.TLSVersion.TLSv1_3;ctx.maximum_version=ssl.TLSVersion.TLSv1_3
    with socket.create_connection((name,443),timeout=12) as sock:
        with ctx.wrap_socket(sock,server_hostname=name) as tls:
            handshake_ip=tls.getpeername()[0];target=dict(name=name,ip=handshake_ip,tls_version=tls.version(),cipher=tls.cipher()[0],certificate_verified=True)
    (d/'camouflage-target.json').write_text(json.dumps(target,indent=2))
    private=d/'engine-private'
    subprocess.run([str(binary),'engine-init','-dir',str(private),'-server-ip',a.server_ip,'-server-name',name],check=True)
    profile=json.loads((private/'profile.json').read_text());profile.update(quic_port=443,tcp_port=443,handshake_server=handshake_ip,handshake_port=443,health_url='http://127.0.0.1:19803/',namespace='ngt-apps')
    (private/'profile.json').write_text(json.dumps(profile));out=private/'configs'
    subprocess.run([str(binary),'engine-plan','-profile',str(private/'profile.json'),'-output',str(out)],check=True)
    common=dict(max_sessions=64,idle_seconds=60,probe_seconds=2)
    native=dict(common,role='server',listen='0.0.0.0:21143',tls=dict(ca=profile['ca'],cert=profile['cert'],key=profile['key'],client_name='entry'),services={'tcp-echo':dict(protocol='tcp',target='127.0.0.1:19801'),'udp-echo':dict(protocol='udp',target='127.0.0.1:19802')})
    (d/'native-server.json').write_text(json.dumps(native));(d/'native-server.json').chmod(0o600)
    # Export only client-side auth and the public CA/certificate. CA/server
    # private keys remain inside the server's protected private directory.
    client=dict(common,role='client',tls=dict(ca='/opt/nextgen-field-a/ca.crt',cert='/opt/nextgen-field-a/client.crt',key='/opt/nextgen-field-a/client.key',server_name=name),endpoints=[dict(name='native-quic',protocol='quic',address=a.server_ip+':21143'),dict(name='native-tls',protocol='tls',address=a.server_ip+':21143')],forwards=[dict(service='tcp-echo',protocol='tcp',listen='127.0.0.1:19811'),dict(service='udp-echo',protocol='udp',listen='127.0.0.1:19812')],status_file='/opt/nextgen-field-a/native-status.json')
    (d/'native-client.json').write_text(json.dumps(client));(d/'native-client.json').chmod(0o600)
    for role in ('server','client'):
        subprocess.run([str(binary),'engine-check','-binary',str(d/'sing-box'),'-sha256',hashlib.sha256((d/'sing-box').read_bytes()).hexdigest(),'-config',str(out/(role+'.json'))],check=True)
    print(json.dumps(dict(prepared=True,camouflage_tls=target['tls_version'],certificate_verified=True,server_private_keys_exported=False)))
if __name__=='__main__':main()
