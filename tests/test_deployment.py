import base64
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import agent
import tunnelctl
import hashlib
import os
import shutil
from model import validate, role_plan

ROOT = Path(__file__).resolve().parents[1]
KEY = base64.b64encode(b"x"*32).decode()
SECRET = "ab"*32

def config():
    return json.loads((ROOT/"deployment.example.json").read_text())

def plan(role="entry", ports=None):
    return role_plan(config(),role,{"entry":KEY,"exit":KEY},SECRET,
                     ports or {"tcp":[48320],"udp":[500,4500,1701,46954,48320,34569]})

class ProfileTests(unittest.TestCase):
    def test_reference_and_pair_addresses(self):
        a,b=plan(),plan("exit")
        self.assertEqual(a["service_peer"],b["service_local"])
        self.assertEqual(a["link_peer"],b["link_local"])
        self.assertEqual(validate(config())["rate_mbit"],120)

    def test_shell_injection_rejected(self):
        for field,value in (("interface","wg-x;touch /tmp/pwn"),("ppp_subnet","10/8;false"),
                            ("rate_mbit","120;false"),("receive_kib",True)):
            c=config();c["tunnel"][field]=value
            with self.subTest(field=field),self.assertRaises((ValueError,TypeError)):
                validate(c)

    def test_overlap_loopback_and_mss_rejected(self):
        for field,value in (("link_subnet","127.0.0.0/30"),("service_subnet","10.77.240.0/30"),
                            ("l2tp_mss",1240),("wg_port",34569)):
            c=config();c["tunnel"][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                validate(c)

    def test_remote_plan_recomputed(self):
        p=plan();p["service_peer"]="10.9.9.9"
        with self.assertRaises(ValueError):
            agent.checked_plan(p)

    @unittest.skipUnless(shutil.which("bash"), "bash syntax validation requires bash")
    def test_all_runtime_shell_parses(self):
        for role in ("entry","exit"):
            files=agent.render(plan(role),KEY)
            for name,content in files.items():
                self.assertNotRegex(content,r"@[A-Z_]+@")
                if content.startswith("#!/bin/bash"):
                    r=subprocess.run(["bash","-n"],input=content,text=True,capture_output=True)
                    self.assertEqual(r.returncode,0,(name,r.stderr))

    def test_auto_detected_tcp_openvpn_has_no_udp_forward(self):
        text=agent.forward_script(plan(ports={"tcp":[46954,48320],"udp":[34569]}))
        self.assertIn("-p tcp -m multiport --dports 46954,48320",text)
        self.assertNotIn("--dports 500,4500",text)
        self.assertIn("-i @WAN@",text)
        self.assertNotIn("--dport 22",text)

    def test_l2tp_mss_handles_syn_ack_and_only_reduces(self):
        text=agent.forward_script(plan("exit"))
        self.assertNotIn("--syn",text)
        self.assertIn("--tcp-flags SYN,RST SYN",text)
        self.assertIn("--mss 1201:65535",text)
        self.assertIn("-o ppp+",text)
        self.assertIn("--pol ipsec",text)

    def test_private_keys_are_not_remote_command_arguments(self):
        files=agent.render(plan(),KEY)
        self.assertIn("PrivateKey = "+KEY,files["/etc/wireguard/wg-game.conf"])
        unit=files["/etc/systemd/system/gaming-raw.service"]
        self.assertNotIn(SECRET,unit)
        self.assertIn("--conf-file",unit)
        self.assertIn("ExecStartPost=-/usr/bin/python3",unit)

    def test_monitor_retains_qos_and_capture_policy(self):
        files=agent.render(plan("exit"),KEY)
        mon=files["/usr/local/sbin/gaming-monitor"]
        self.assertIn("/usr/local/sbin/gaming-qos",mon)
        self.assertIn("gaming-receive-buffer 8192",mon)
        self.assertIn("300",mon)

    @unittest.skipUnless(os.name == "posix", "POSIX permissions and paths require Linux")
    def test_backup_modes_and_scoped_rollback(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);st=root/"state";st.mkdir();owned=root/"owned";owned.write_text("old")
            unrelated=root/"independent";unrelated.write_text("untouched")
            def fake(args,*a,**kw):
                return SimpleNamespace(returncode=0,stdout="",stderr="")
            with patch.object(agent,"STATE",st),patch.object(agent,"run",side_effect=fake) as calls:
                b=agent.snapshot("a"*16,{str(owned):"new"},plan())
                owned.write_text("new")
                result=agent.rollback("a"*16)
                self.assertEqual(owned.read_text(),"old")
                self.assertEqual(unrelated.read_text(),"untouched")
                self.assertEqual(result["rolled_back"],"a"*16)
                all_commands=[str(c.args[0]) for c in calls.call_args_list]
                self.assertFalse(any("flush" in x for x in all_commands))
                self.assertFalse(any("'ssh'" in x or "'ocserv'" in x for x in all_commands))
                self.assertEqual(b.stat().st_mode&0o777,0o700)

    def test_boot_orders_firewall_carrier_wireguard_and_forwarding(self):
        for role in ("entry", "exit"):
            files=agent.render(plan(role),KEY)
            raw=files["/etc/systemd/system/gaming-raw.service"]
            forward=files["/etc/systemd/system/gaming-forward.service"]
            wg=files["/etc/systemd/system/wg-quick@wg-game.service.d/10-carrier.conf"]
            self.assertIn("After=systemd-sysctl.service netfilter-persistent.service ufw.service nftables.service",raw)
            self.assertIn("After=gaming-address.service gaming-raw.service wg-quick@wg-game.service",forward)
            for value in (raw,forward,wg):
                self.assertIn("StartLimitIntervalSec=0",value)
                self.assertIn("Restart=on-failure",value)
            self.assertIn("After=gaming-raw.service gaming-address.service",wg)

    def test_rollback_nonexistent_transaction_is_noop(self):
        with tempfile.TemporaryDirectory() as d,patch.object(agent,"STATE",Path(d)),patch.object(agent,"run") as run:
            self.assertEqual(agent.rollback("b"*16),{"noop":True})
            run.assert_not_called()

    def exercise_transaction(self, fail_start=False):
        # Real rendering/files/state; all host paths and privileged commands isolated.
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            def mapped(value):
                p=Path(value)
                if str(p).startswith(("/etc/","/var/lib/","/usr/local/","/proc/sys/")):
                    return root/str(p).lstrip("/")
                return p
            etc=mapped("/etc/gaming-tunnel");st=mapped("/var/lib/gaming-tunnel")
            etc.mkdir(parents=True);st.mkdir(parents=True)
            (etc/"private.key").write_text(KEY)
            for name,value in (("net/ipv4/ip_forward","0"),("net/core/rmem_max","16777216")):
                p=mapped("/proc/sys/"+name);p.parent.mkdir(parents=True,exist_ok=True);p.write_text(value)
            commands=[]
            def fake(args,check=True,data=None):
                commands.append(args)
                if args[:4]==["ip","-j","route","get"]:
                    return SimpleNamespace(returncode=0,stdout='[{"dev":"ens3"}]',stderr="")
                if args[:2]==["iptables","-t"]:
                    return SimpleNamespace(returncode=1,stdout="",stderr="")
                if fail_start and args==["systemctl","enable","--now","wg-quick@wg-game"]:
                    raise RuntimeError("simulated WireGuard startup failure")
                if args[:2]==["sysctl","-w"]:
                    key,value=args[2].split("=",1)
                    mapped("/proc/sys/"+key.replace(".","/")).write_text(value)
                return SimpleNamespace(returncode=0,stdout="",stderr="")
            with patch.object(agent,"Path",side_effect=mapped),patch.object(agent,"ETC",etc),patch.object(agent,"STATE",st),patch.object(agent,"run",side_effect=fake):
                agent.save_state(dict(phase="prepared",interface="wg-game"))
                payload=dict(plan=plan(),transaction="c"*16)
                if fail_start:
                    with self.assertRaisesRegex(RuntimeError,"simulated"):
                        agent.apply(payload)
                else:
                    agent.apply(payload)
                    agent.activate()
                    self.assertEqual(agent.state()["phase"],"active")
                    agent.commit("c"*16)
                    self.assertEqual(agent.apply(payload),{"noop":True,"transaction":"c"*16})
                self.assertTrue(mapped("/etc/wireguard/wg-game.conf").exists())
                agent.rollback("c"*16)
                self.assertFalse(mapped("/etc/wireguard/wg-game.conf").exists())
                self.assertEqual(agent.state()["phase"],"prepared")
                self.assertEqual(mapped("/proc/sys/net/ipv4/ip_forward").read_text(),"0")
                self.assertFalse(any(c[:2]==["systemctl","restart"] for c in commands))

    @unittest.skipUnless(os.name == "posix", "isolated host transaction requires POSIX paths")
    def test_isolated_full_transaction_and_idempotent_apply(self):
        self.exercise_transaction()

    @unittest.skipUnless(os.name == "posix", "isolated host transaction requires POSIX paths")
    def test_isolated_partial_install_can_be_rolled_back(self):
        self.exercise_transaction(fail_start=True)

    def test_controller_preserves_original_rollback_on_unchanged_pair(self):
        with tempfile.TemporaryDirectory() as d:
            directory=Path(d);binary=directory/"udp2raw";binary.write_bytes(b"test fixture")
            args=SimpleNamespace(binary=str(binary),sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),install_deps=False)
            calls=[]
            def invoke(c,role,action,payload=None,tag=None,**kw):
                calls.append((role,action,tag))
                if action=="prepare":return dict(public_key=KEY,audit=dict(vpn_ports={"udp":[34569],"tcp":[]}))
                if action=="apply":return dict(noop=True,transaction="d"*16)
                return {}
            with patch.object(tunnelctl,"upload",return_value="/tmp/fixture/agent.py"),patch.object(tunnelctl,"invoke",side_effect=invoke),patch.object(tunnelctl,"local_secret",return_value=(directory,SECRET)):
                tunnelctl.deploy(args,config())
            self.assertEqual((directory/"last-transaction.txt").read_text(),"d"*16)
            self.assertEqual([t for r,a,t in calls if a=="commit"],["d"*16,"d"*16])

    def test_prepare_does_not_run_on_import(self):
        self.assertTrue(callable(agent.prepare))
        self.assertTrue(callable(agent.bench_stop))

if __name__=="__main__":
    unittest.main()
