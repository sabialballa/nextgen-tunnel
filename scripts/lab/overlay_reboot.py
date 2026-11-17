"""An explicitly authorized sequential field reboot, strict pins, in-memory password."""
import argparse,getpass,json,pathlib,socket,sys,time
from remote_audit import paramiko,open_socket,STATE

REMOTE='/opt/nextgen-stack-stage/overlay-hour-v2'
def main():
 p=argparse.ArgumentParser();p.add_argument('--host',required=True);p.add_argument('--node',choices=['iran','turkey'],required=True);p.add_argument('--direct-interface',type=int,required=True);p.add_argument('--bind-ip',required=True);a=p.parse_args();socket.inet_aton(a.host);socket.inet_aton(a.bind_ip)
 password=getpass.getpass('SSH password (memory only; not saved): ')
 def connect():
  client=paramiko.SSHClient();client.load_host_keys(str(STATE/'known_hosts'));client.set_missing_host_key_policy(paramiko.RejectPolicy())
  sock=open_socket(a.host,22,a.direct_interface,a.bind_ip,10)
  try:client.connect(a.host,username='root',password=password,sock=sock,look_for_keys=False,allow_agent=False,timeout=10,banner_timeout=10,auth_timeout=10,disabled_algorithms={'keys':['ssh-ed25519','ecdsa-sha2-nistp256','ecdsa-sha2-nistp384','ecdsa-sha2-nistp521','ssh-rsa']})
  except BaseException:client.close();sock.close();raise
  return client
 def execute(client,command,timeout=25):
  _,out,err=client.exec_command(command,timeout=timeout);stdout=out.read().decode();stderr=err.read().decode();status=out.channel.recv_exit_status()
  if status:raise RuntimeError('remote operation failed: '+stderr[-500:])
  return stdout
 client=connect()
 try:
  sftp=client.open_sftp()
  with sftp.open(REMOTE+'/hour.json') as f:hour=json.load(f)
  assert hour['complete'] and hour['elapsed_seconds']>=3600,'full hour must finish before reboot'
  before=execute(client,'cat /proc/sys/kernel/random/boot_id').strip()
  with sftp.open(REMOTE+'/boot-before.txt') as f:assert f.read().decode().strip()==before,'already rebooted; refuse another reboot'
  assert not sftp.listdir(REMOTE).count('reboot-issued.json'),'reboot already issued'
  issued=dict(node=a.node,boot_before=before,issued_wall_time=time.time())
  with sftp.open(REMOTE+'/reboot-issued.json','w') as f:f.write(json.dumps(issued))
  sftp.chmod(REMOTE+'/reboot-issued.json',0o600);sftp.close()
  execute(client,'systemd-run --quiet --unit=nextgen-overlay-authorized-reboot --on-active=3s /usr/bin/systemctl reboot')
 finally:client.close()
 print(json.dumps({'node':a.node,'reboot_issued':True}),flush=True)
 start=time.monotonic();time.sleep(10);last=0;report=dict(node=a.node,before_boot_id=before,reboot_verified=False,permanent_services_manually_started=False)
 try:
  while time.monotonic()-start<600:
   client=None
   try:
    client=connect();after=execute(client,'cat /proc/sys/kernel/random/boot_id').strip()
    if after!=before:
     output=execute(client,f'python3 -B /usr/local/lib/nextgen-overlay-hour/overlay_hour.py reboot-check --node {a.node}',timeout=60);result=json.loads(output)
     if result['success']:
      report.update(reboot_verified=True,after_boot_id=after,observation_elapsed_seconds=time.monotonic()-start,recovery=result);break
   except (paramiko.BadHostKeyException,paramiko.AuthenticationException):raise
   except (OSError,paramiko.SSHException,RuntimeError,ValueError):pass
   finally:
    if client:client.close()
   if time.monotonic()-last>=25:print(json.dumps({'node':a.node,'waiting_for_automatic_recovery_seconds':round(time.monotonic()-start)}),flush=True);last=time.monotonic()
   time.sleep(5)
  if not report['reboot_verified']:raise RuntimeError('automatic recovery not verified within600seconds; no manual start attempted')
 finally:
  password=None;(STATE/(a.node+'-overlay-reboot-observation.json')).write_text(json.dumps(report,indent=2)+'\n')
 print(json.dumps({'node':a.node,'reboot_verified':report['reboot_verified'],'observation_elapsed_seconds':report.get('observation_elapsed_seconds')}),flush=True)
if __name__=='__main__':main()
