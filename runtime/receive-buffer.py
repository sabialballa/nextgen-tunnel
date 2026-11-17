#!/usr/bin/python3
import os,ctypes,socket,subprocess,json,sys,time,platform
if platform.machine()!='x86_64':raise RuntimeError('This helper was validated on x86_64 only')
kib=int(sys.argv[1])
if not 1024<=kib<=10240:raise ValueError('Requested buffer outside validated range')
libc=ctypes.CDLL(None,use_errno=True)
for attempt in range(20):
 pid=int(subprocess.check_output(['systemctl','show','gaming-raw','-p','MainPID','--value'],text=True));result=[]
 if pid<=0:time.sleep(.1);continue
 try:pfd=os.pidfd_open(pid,0)
 except ProcessLookupError:time.sleep(.1);continue
 try:
  for v in os.listdir('/proc/'+str(pid)+'/fd'):
   if not v.isdigit():continue
   fd=int(v);dup=libc.syscall(438,pfd,fd,0)
   if dup<0:continue
   try:
    with socket.socket(fileno=dup) as s:
     if int(s.family)!=17 or s.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)!=socket.SOCK_DGRAM:continue
     old=s.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF);changed=old!=2*kib*1024
     if changed:s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,kib*1024)
     new=s.getsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF)
     if new<2*kib*1024:raise RuntimeError('Kernel did not accept requested receive buffer')
     result.append({'pid':pid,'fd':fd,'old_receive_bytes':old,'new_receive_bytes':new,'changed':changed})
   except OSError:pass
 finally:os.close(pfd)
 if result:
  if any(r['changed'] for r in result):print(json.dumps(result))
  sys.exit(0)
 time.sleep(.1)
raise RuntimeError('No carrier AF_PACKET receive socket accessible; no unrelated socket changed')
