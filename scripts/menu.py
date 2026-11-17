#!/usr/bin/env python3
"""Interactive Linux entry point; delegate mutations to the owned installers."""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT=Path(__file__).resolve().parents[1]
RELEASE='https://github.com/sabialballa/nextgen-tunnel/releases/download/v0.3.0-rc3/'
BUNDLE='nextgen-tunnel-0.3.0-rc3-linux-amd64-full.tar.gz'
BUNDLE_SHA='85ac53b1e0e94e15ad53a92c2d33490321c4793aae8c52075de14b314106cc4f'
CORE_SHA='96cec972279a1d7a02f13aed4dd6fd3029b581576edd8f48bc598abb9726433f'
ENGINE_SHA='606f883d1aa3c624f38aa3f99bf0df02e3999f9aa0ff5826e0dd9c1b9f964baf'
UNITS=['nextgen-engine.service','nextgen-site.service','nextgen-site-watchdog.timer']+['nextgen-overlay-ngo-'+k+'.service' for k in ['gre','vxlan','ipip']]

def user_id():return os.geteuid() if hasattr(os,'geteuid') else -1

def digest(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for chunk in iter(lambda:f.read(1<<20),b''):h.update(chunk)
    return h.hexdigest()

def verify_handshake(address,name,port):
    context=ssl.create_default_context();context.minimum_version=ssl.TLSVersion.TLSv1_3
    with socket.create_connection((address,port),timeout=8) as raw:
        with context.wrap_socket(raw,server_hostname=name) as peer:
            if peer.version()!='TLSv1.3':raise ValueError('مقصد handshake باید TLS 1.3 معتبر داشته باشد.')

def safe_directory(path):
    path=Path(path).expanduser().absolute()
    for parent in [path,*path.parents]:
        if parent.is_symlink():raise ValueError('مسیر داده نباید symlink باشد.')
    path.mkdir(mode=0o700,parents=True,exist_ok=True)
    st=path.stat()
    if st.st_uid!=user_id() or st.st_mode&0o077:raise ValueError('پوشهٔ داده باید متعلق به شما و با مجوز 700 باشد: '+str(path))
    return path

def download_bundle(cache):
    """Pinned archive plus manifest, safe extraction, publish cache atomically."""
    if __package__:
        from .verify_bundle import verify
    else:
        from verify_bundle import verify
    cache=safe_directory(cache);ready=cache/'runtime-0.3.0-rc3'
    if ready.exists():
        if ready.is_symlink() or digest(ready/'bin/nextgen-tunnel')!=CORE_SHA or digest(ready/'bin/sing-box')!=ENGINE_SHA:raise ValueError('بستهٔ موجود تغییر کرده؛ مسیر cache را بررسی کنید.')
        return ready
    with tempfile.TemporaryDirectory(prefix='download-',dir=cache) as temp:
        work=Path(temp);archive=work/BUNDLE
        print('دریافت بستهٔ کامل Linux x64 (حدود ۱۰۴ MiB)…')
        request=urllib.request.Request(RELEASE+BUNDLE,headers={'User-Agent':'nextgen-menu/1'})
        with urllib.request.urlopen(request,timeout=30) as response,archive.open('xb') as out:
            size=0
            while True:
                chunk=response.read(1<<20)
                if not chunk:break
                size+=len(chunk)
                if size>160*1024**2:raise ValueError('اندازهٔ دانلود بیش از حد است.')
                out.write(chunk)
        if digest(archive)!=BUNDLE_SHA:raise ValueError('SHA256 بسته تطبیق ندارد؛ اجرا نشد.')
        verify(archive)
        extracted=work/'runtime';extracted.mkdir(mode=0o700)
        with tarfile.open(archive,'r:gz') as bundle:
            for member in bundle:
                parts=Path(member.name).parts[1:];target=extracted.joinpath(*parts)
                target.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
                with bundle.extractfile(member) as src,target.open('xb') as dst:shutil.copyfileobj(src,dst)
                target.chmod(0o755 if parts[0]=='bin' else 0o600)
        if digest(extracted/'bin/nextgen-tunnel')!=CORE_SHA or digest(extracted/'bin/sing-box')!=ENGINE_SHA:raise ValueError('باینری بسته با نسخهٔ آزمایش‌شده یکسان نیست.')
        extracted.rename(ready)
    return ready

class Menu:
    def __init__(self,root=ROOT,ask=None):
        self.root=Path(root);self.ask=ask or input
        self.home=Path('/var/lib/nextgen-menu') if user_id()==0 else Path.home()/'.local/share/nextgen-menu'
        self.cache=Path('/var/cache/nextgen-menu') if user_id()==0 else Path.home()/'.cache/nextgen-menu'

    def prompt(self,text,default=''):
        answer=self.ask(text+(f' [{default}]' if default else '')+': ').strip()
        return answer or str(default)

    def path(self,text,default='',new=False):
        value=self.prompt(text,default)
        if not value:raise ValueError('مسیر وارد نشده است.')
        p=Path(value).expanduser().absolute()
        if new:
            if p.exists() or p.is_symlink():raise ValueError('مسیر جدید باید هنوز وجود نداشته باشد.')
        elif not p.is_file():raise ValueError('فایل پیدا نشد: '+str(p))
        return p

    def root_required(self):
        if user_id()!=0:raise ValueError('این گزینه را با کاربر root یا sudo اجرا کنید.')

    def command(self,args,check=True,timeout=180,quiet=False):
        result=subprocess.run([str(x) for x in args],timeout=timeout,capture_output=quiet,text=quiet)
        if check and result.returncode:
            if quiet:print((result.stdout+result.stderr)[-4000:])
            raise ValueError('عملیات موفق نبود؛ خروجی بالا را بررسی کنید.')
        return result.returncode

    def script(self,name,*args):return [sys.executable,str(self.root/'scripts'/name),*map(str,args)]

    def approve(self,description):
        print('\n'+description)
        return self.prompt('برای اعمال yes بنویسید؛ Enter یعنی انصراف').casefold() in ('yes','بله')

    def apply(self,args,description):
        self.root_required();self.command(args,quiet=True)
        if self.approve(description):self.command([*args,'--apply'])
        else:print('اعمال نشد.')

    def runtime(self):
        if platform.machine().lower() not in ('x86_64','amd64'):raise ValueError('بستهٔ آماده فعلاً فقط Linux x64 است؛ روی ARM از راهنمای ساخت استفاده کنید.')
        installed=Path('/usr/local/lib/nextgen-stack')
        if all((installed/name).is_file() and digest(installed/name)==sha for name,sha in [('nextgen-tunnel',CORE_SHA),('sing-box',ENGINE_SHA)]):return installed
        return download_bundle(self.cache)/'bin'

    def prepare(self):
        print('\n1) ساخت پروفایل listener و کلیدهای engine\n2) ساخت CA و کلیدهای هستهٔ مستقل\n3) ساخت carrier از تنظیم engine آماده\n4) ساخت کلید WireGuard روی همین سرور\n5) ساخت تنظیم Site-to-Site این سمت\n0) برگشت')
        choice=self.prompt('انتخاب')
        if choice=='0':return
        self.root_required();home=safe_directory(self.home)
        if choice=='1':
            binary=self.runtime()/'nextgen-tunnel';directory=self.path('پوشهٔ جدید و خصوصی پروفایل',home/'profile',new=True)
            ip=str(ipaddress.IPv4Address(self.prompt('IPv4 عمومی سرور listener')));name=self.prompt('نام واقعی TLS/SNI مقصد handshake')
            if not name:raise ValueError('نام TLS/SNI لازم است.')
            handshake=str(ipaddress.IPv4Address(self.prompt('IP مقصد واقعی handshake با TLS 1.3 معتبر')))
            if ipaddress.ip_address(handshake).is_loopback:raise ValueError('مقصد handshake نباید loopback باشد.')
            port=int(self.prompt('پورت TLS مقصد handshake','443'))
            if not 1<=port<=65535:raise ValueError('پورت نامعتبر است.')
            print('بررسی گواهی، نام و TLS 1.3 مقصد…');verify_handshake(handshake,name,port)
            self.command([binary,'engine-init','-dir',directory,'-server-ip',ip,'-server-name',name])
            profile=directory/'profile.json'
            original=json.loads(profile.read_text())
            key=next((k for k in original if k in ('handshake_server','reality_handshake_server')),None)
            if not key:raise ValueError('فیلد handshake در نسخهٔ هسته شناخته نشد؛ profile.json را طبق راهنما تنظیم کنید.')
            original[key]=handshake;original['handshake_port']=port;profile.write_text(json.dumps(original,indent=2)+'\n');profile.chmod(0o600)
            output=directory/'configs';self.command([binary,'engine-plan','-profile',profile,'-output',output])
            print('پروفایل در '+str(directory)+' ساخته شد. فقط فایل‌های سمت client و CA عمومی را امن منتقل کنید؛ CA.key و کلید سرور را منتقل نکنید.')
            print('TLS مقصد با نام واردشده تأیید شد؛ تست اتصال واقعی دو سرور همچنان لازم است. راهنما: https://github.com/sabialballa/nextgen-tunnel/blob/main/docs/engine-site.md')
        elif choice=='2':
            binary=self.runtime()/'nextgen-tunnel';directory=self.path('پوشهٔ جدید PKI',home/'pki',new=True)
            self.command([binary,'pki','-dir',directory,'-server-name',self.prompt('نام TLS سرور','tunnel.internal'),'-client-name',self.prompt('نام کلاینت','entry')])
        elif choice=='3':
            role={'1':'listener','2':'initiator'}.get(self.prompt('نقش: 1=listener، 2=initiator'))
            if not role:raise ValueError('نقش نامعتبر است.')
            source=self.path('مسیر server.json یا client.json آماده');target=self.path('فایل جدید carrier',home/'carrier.json',new=True)
            port=int(self.prompt('پورت TCP عمومی listener؛ در هر دو سمت یکسان','443'))
            if not 1<=port<=65535:raise ValueError('پورت نامعتبر است.')
            self.command(self.script('stack_prepare.py','--role',role,'--redundant','--public-port',port,'--source',source,'--output',target))
            print('carrier ساخته شد. برای نصب، site.json و کلید عمومی peer را طبق راهنمای engine/site آماده کنید.')
        elif choice=='4':
            directory=self.path('پوشهٔ جدید کلید WireGuard',home/'wg',new=True)
            self.command(self.script('site.py','keygen','--directory',directory));print('فقط public.key را با طرف مقابل مبادله کنید.')
        elif choice=='5':self.site_config(home)
        else:print('گزینه نامعتبر است.')

    def site_config(self,home):
        role=self.prompt('نقش: 1=listener، 2=initiator')
        if role not in ('1','2'):raise ValueError('نقش نامعتبر است.')
        own='1' if role=='1' else '2';other='2' if own=='1' else '1'
        private=self.path('کلید خصوصی WireGuard همین سرور',home/'wg/private.key')
        peer=self.prompt('کلید عمومی WireGuard طرف مقابل')
        if len(base64.b64decode(peer,validate=True))!=32:raise ValueError('کلید عمومی باید ۳۲ بایت base64 باشد.')
        local4=str(ipaddress.IPv4Interface(self.prompt('آدرس IPv4 این سمت',f'10.77.240.{own}/30')))
        remote4=str(ipaddress.IPv4Address(self.prompt('IPv4 طرف مقابل',f'10.77.240.{other}')))
        local6=str(ipaddress.IPv6Interface(self.prompt('آدرس IPv6 این سمت',f'fd77:240::{own}/126')))
        remote6=str(ipaddress.IPv6Address(self.prompt('IPv6 طرف مقابل',f'fd77:240::{other}')))
        cfg=dict(name='ngt-site-main',private_key_file=str(private),peer_public_key=peer,addresses=[local4,local6],remote_routes=[remote4+'/32',remote6+'/128'],listen_port=51850 if role=='1' else 51860,mtu=1280)
        if role=='1':cfg['redundant_listener_port']=51851
        else:cfg.update(endpoint='127.0.0.1:51811',persistent_keepalive=1)
        target=self.path('فایل جدید تنظیم سایت',home/'site.json',new=True);safe_directory(target.parent)
        fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'w') as out:json.dump(cfg,out,indent=2)
        print('تنظیم این سمت ساخته شد: '+str(target)+'؛ همین مراحل را با نقش مخالف و کلید مستقل روی سرور دیگر انجام دهید.')

    def stack(self):
        self.root_required()
        print('\n1) نصب engine/site\n2) به‌روزرسانی\n3) بازیابی تراکنش ناتمام\n0) برگشت')
        choice=self.prompt('انتخاب');action={'1':'install','2':'update','3':'recover'}.get(choice)
        if not action:return
        args=self.script('stack_install.py',action)
        if action!='recover':
            binary=self.runtime();engine=self.path('فایل carrier/engine آماده','/etc/nextgen-stack/engine.json');site=self.path('فایل site.json آماده','/etc/nextgen-stack/site.json')
            args+=['--binary',str(binary/'nextgen-tunnel'),'--sha256',CORE_SHA,'--engine',str(binary/'sing-box'),'--engine-sha256',ENGINE_SHA,'--engine-config',str(engine),'--site-config',str(site)]
        self.apply(args,'این عملیات فقط نصب مدیریت‌شدهٔ engine/site را تغییر می‌دهد؛ برای نصب روی هر سرور تنظیمات همان سمت لازم است.')

    def overlays(self):
        self.root_required();kind={'1':'gre','2':'vxlan','3':'ipip'}.get(self.prompt('نوع تونل: 1=GRE، 2=VXLAN، 3=IPIP'))
        if not kind:raise ValueError('نوع تونل نامعتبر است.')
        action={'1':'install','2':'status','3':'remove'}.get(self.prompt('1=نصب، 2=وضعیت، 3=حذف'))
        if not action:raise ValueError('گزینه نامعتبر است.')
        installed=Path('/etc/nextgen-overlays')/('ngo-'+kind+'.json')
        if action=='install' and not installed.exists():
            local=str(ipaddress.IPv4Address(self.prompt('IP خصوصی همین سمت روی wg0','10.77.240.1')));remote=str(ipaddress.IPv4Address(self.prompt('IP خصوصی سمت مقابل روی wg0','10.77.240.2')))
            side=self.prompt('شمارهٔ این سمت: 1 یا 2','1' if local.endswith('.1') else '2')
            if side not in ('1','2'):raise ValueError('سمت باید 1 یا 2 باشد.')
            subnet={'gre':250,'vxlan':251,'ipip':252}[kind]
            address=str(ipaddress.IPv4Interface(self.prompt('آدرس جدید overlay',f'10.78.{subnet}.{side}/30')))
            cfg=dict(name='ngo-'+kind,namespace=self.prompt('namespace سایت موجود','ngt-site-main'),kind=kind,local=local,remote=remote,address=address,mtu=1200)
            if kind=='vxlan':cfg.update(vni=10771,port=4789)
            if __package__:
                from .overlay import validate
            else:
                from overlay import validate
            validate(cfg);directory=safe_directory(self.home/'overlays')
            fd,filename=tempfile.mkstemp(prefix=kind+'-',suffix='.json',dir=directory)
            with os.fdopen(fd,'w') as out:json.dump(cfg,out)
            config=Path(filename)
        else:config=self.path('فایل تنظیم همان تونل',installed)
        args=self.script('overlay_service.py',action,'--config',config)
        if action=='status':self.command(args)
        else:self.apply(args,'تونل '+kind.upper()+(' نصب می‌شود.' if action=='install' else ' و سرویس متعلق به همین تنظیم حذف می‌شوند.'))

    def status(self):
        print('\nوضعیت سرویس‌ها:')
        names=['موتور TCP','سایت خصوصی','بازیابی خودکار','GRE','VXLAN','IPIP','هستهٔ مستقل']
        for unit,label in zip([*UNITS,'nextgen-tunnel.service'],names):
            result=subprocess.run(['systemctl','is-active',unit],capture_output=True,text=True,timeout=5)
            state=result.stdout.strip();print(label+': '+{'active':'فعال','inactive':'غیرفعال','failed':'خطا','unknown':'نصب نشده'}.get(state,state or 'نامشخص'))

    def test(self):
        print('\n1) تست مسیرهای هسته با client.json\n2) Ping محدود روی سایت/overlay\n0) برگشت')
        choice=self.prompt('انتخاب')
        if choice=='1':self.command([self.runtime()/'nextgen-tunnel','probe','-config',self.path('فایل client.json')])
        elif choice=='2':
            self.root_required();namespace=self.prompt('namespace','ngt-site-main')
            import re
            if not re.fullmatch(r'ngt-site-[a-z0-9_-]{1,18}',namespace):raise ValueError('namespace نامعتبر است.')
            target=str(ipaddress.ip_address(self.prompt('IP خصوصی مقصد','10.78.252.2')))
            self.command(['ip','netns','exec',namespace,'ping','-n','-c','5','-W','2',target],timeout=20)

    def core(self):
        self.root_required();print('\n1) نصب هستهٔ مستقل\n2) به‌روزرسانی\n3) بازیابی تراکنش\n4) حذف هستهٔ مستقل\n0) برگشت')
        action={'1':'install','2':'update','3':'recover','4':'uninstall'}.get(self.prompt('انتخاب'))
        if not action:return
        args=self.script('host_install.py',action)
        if action in ('install','update'):args+=['--binary',str(self.runtime()/'nextgen-tunnel'),'--sha256',CORE_SHA,'--config',str(self.path('تنظیم server.json یا client.json همین سمت'))]
        self.apply(args,'این گزینه فقط سرویس مستقل nextgen-tunnel را مدیریت می‌کند؛ '+action)

    def run(self):
        actions={'1':lambda:print('باینری آماده: '+str(self.runtime())),'2':self.prepare,'3':self.stack,'4':self.overlays,'5':self.status,'6':self.test,'7':lambda:self.command(['journalctl','--no-pager','-n','60',*sum((['-u',u] for u in UNITS),[])],check=False),'8':self.core}
        while True:
            print('\n=== NEXTGEN TUNNEL | منوی مدیریت ===\n1) دریافت / بررسی بستهٔ آماده\n2) آماده‌سازی کلید و تنظیمات\n3) نصب / به‌روزرسانی engine و Site-to-Site\n4) مدیریت GRE / VXLAN / IPIP\n5) وضعیت سرویس‌ها\n6) تست اتصال\n7) گزارش خطاها\n8) مدیریت هستهٔ مستقل\n0) خروج')
            try:
                choice=self.prompt('انتخاب')
                if choice=='0':return
                if choice not in actions:print('گزینه نامعتبر است.');continue
                actions[choice]()
            except (EOFError,KeyboardInterrupt):print('\nخروج.');return
            except (ValueError,OSError,subprocess.SubprocessError,KeyError) as exc:print('خطا: '+str(exc))

def main():
    parser=argparse.ArgumentParser(description='منوی نصب و مدیریت Nextgen Tunnel روی Linux');parser.parse_args()
    if sys.platform!='linux':raise SystemExit('این منو را روی سرور Linux اجرا کنید.')
    Menu().run()
if __name__=='__main__':main()
