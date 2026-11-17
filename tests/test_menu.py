import contextlib
import base64
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from scripts import menu

class MenuTests(unittest.TestCase):
    def test_open_and_exit_has_no_network_commands_or_writes(self):
        with mock.patch('urllib.request.urlopen') as network,mock.patch('subprocess.run') as command,mock.patch.object(Path,'mkdir') as mkdir,contextlib.redirect_stdout(io.StringIO()) as output:
            menu.Menu(ask=lambda _: '0').run()
        network.assert_not_called();command.assert_not_called();mkdir.assert_not_called()
        self.assertIn('GRE / VXLAN / IPIP',output.getvalue())

    def test_cancel_does_not_apply(self):
        ui=menu.Menu(ask=lambda _: '')
        with mock.patch.object(ui,'root_required'),mock.patch.object(ui,'command') as command,contextlib.redirect_stdout(io.StringIO()):
            ui.apply(['python3','owned-installer','install'],'توضیح')
        self.assertEqual(command.call_count,1)
        self.assertNotIn('--apply',command.call_args.args[0])

    def test_apply_uses_the_same_reviewed_arguments(self):
        ui=menu.Menu(ask=lambda _: 'yes');args=['python3','installer','install','--config','/private/config with spaces.json']
        with mock.patch.object(ui,'root_required'),mock.patch.object(ui,'command') as command,contextlib.redirect_stdout(io.StringIO()):ui.apply(args,'نصب')
        self.assertEqual(command.call_args_list[0].args[0],args)
        self.assertEqual(command.call_args_list[1].args[0],[*args,'--apply'])

    def test_wrong_download_is_rejected_before_archive_parsing(self):
        with tempfile.TemporaryDirectory() as directory:
            cache=Path(directory)
            with mock.patch.object(menu,'safe_directory',return_value=cache),mock.patch('urllib.request.urlopen',return_value=io.BytesIO(b'wrong archive')),mock.patch('scripts.verify_bundle.verify') as verify,contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError,'SHA256'):menu.download_bundle(cache)
                verify.assert_not_called()
            self.assertFalse((cache/'runtime-0.3.0-rc3').exists())

    def test_arm_cannot_download_or_execute_amd64_runtime(self):
        with mock.patch('platform.machine',return_value='aarch64'),mock.patch.object(menu,'download_bundle') as download:
            with self.assertRaises(ValueError):menu.Menu().runtime()
            download.assert_not_called()

    def test_eof_leaves_menu_without_commands(self):
        with mock.patch('subprocess.run') as command,contextlib.redirect_stdout(io.StringIO()):menu.Menu(ask=mock.Mock(side_effect=EOFError)).run()
        command.assert_not_called()

    def test_invalid_handshake_never_creates_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            home=Path(directory);answers=iter(['1',str(home/'profile'),'203.0.113.1','tls.example.org','198.51.100.1','443'])
            ui=menu.Menu(ask=lambda _:next(answers))
            with mock.patch.object(ui,'root_required'),mock.patch.object(menu,'safe_directory',return_value=home),mock.patch.object(ui,'runtime',return_value=home),mock.patch.object(menu,'verify_handshake',side_effect=ValueError('certificate rejected')),mock.patch.object(ui,'command') as command,contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(ValueError):ui.prepare()
            command.assert_not_called();self.assertFalse((home/'profile').exists())

    @unittest.skipUnless(os.name=='posix','POSIX private-file permissions')
    def test_site_wizard_keeps_private_config_and_only_loopback_carrier(self):
        with tempfile.TemporaryDirectory() as directory:
            home=Path(directory);private=home/'private.key';private.write_text(base64.b64encode(b'k'*32).decode());private.chmod(0o600)
            target=home/'site.json';answers=iter(['2',str(private),base64.b64encode(b'p'*32).decode(),'','','','',str(target)])
            ui=menu.Menu(ask=lambda _:next(answers))
            with mock.patch('subprocess.run') as command,contextlib.redirect_stdout(io.StringIO()):ui.site_config(home)
            command.assert_not_called();cfg=json.loads(target.read_text())
            self.assertEqual(target.stat().st_mode&0o777,0o600)
            self.assertEqual(cfg['endpoint'],'127.0.0.1:51811')
            self.assertNotIn('0.0.0.0/0',cfg['remote_routes'])

if __name__=='__main__':unittest.main()
