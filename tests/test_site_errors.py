import importlib.util
from pathlib import Path
from types import SimpleNamespace
import subprocess,sys,unittest
from unittest import mock

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'
def module(name,filename):
    spec=importlib.util.spec_from_file_location(name,SCRIPTS/filename)
    value=importlib.util.module_from_spec(spec)
    with mock.patch.object(sys,'path',[str(SCRIPTS),*sys.path]):spec.loader.exec_module(value)
    return value
site=module('nextgen_site_errors','site.py')
stack=module('nextgen_stack_errors','stack_install.py')

class SiteDiagnosticTests(unittest.TestCase):
    def test_wireguard_error_retains_reason_but_redacts_key(self):
        secret='A'*43+'='
        result=SimpleNamespace(returncode=1,stdout='',stderr='Unable to modify interface: Address already in use\nPrivateKey = '+secret)
        with mock.patch.object(site.subprocess,'run',return_value=result):
            with self.assertRaises(ValueError) as caught:site.run(['wg','setconf','test-interface','/private/wg.conf'])
        self.assertIn('Address already in use',str(caught.exception));self.assertNotIn(secret,str(caught.exception))

    def test_service_failure_captures_child_error_before_rollback(self):
        secret='B'*43+'='
        journal=SimpleNamespace(stdout='old journal line\nsite operation failed: wg setconf failed (exit 1): Operation not permitted '+secret+'\n')
        with mock.patch.object(stack,'run',side_effect=[subprocess.CalledProcessError(1,['systemctl','start','nextgen-site.service']),journal]):
            with self.assertRaises(ValueError) as caught:stack.start_unit('nextgen-site.service')
        self.assertIn('Operation not permitted',str(caught.exception));self.assertNotIn(secret,str(caught.exception))

    def test_unavailable_journal_does_not_hide_start_failure(self):
        with mock.patch.object(stack,'run',side_effect=[subprocess.CalledProcessError(1,['systemctl','start','nextgen-site.service']),OSError('journal unavailable')]):
            with self.assertRaisesRegex(ValueError,'nextgen-site.service: See journalctl'):stack.start_unit('nextgen-site.service')

if __name__=='__main__':unittest.main()
