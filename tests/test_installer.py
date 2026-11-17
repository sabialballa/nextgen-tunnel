import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("host_install", Path(__file__).parents[1] / "scripts/host_install.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)

class InstallerSafetyTests(unittest.TestCase):
    def test_ubuntu_2604_passes_preflight_without_mutating_system(self):
        release='ID=ubuntu\nVERSION_ID="26.04"\nPRETTY_NAME="Ubuntu 26.04.1 LTS"\n'
        fake=SimpleNamespace(returncode=0,stdout='test inventory')
        with patch.object(installer.sys,'platform','linux'),patch.object(installer.Path,'read_text',return_value=release),patch.object(installer.Path,'exists',return_value=True),patch.object(installer.shutil,'which',return_value='/usr/bin/tool'),patch.object(installer,'run',return_value=fake) as run:
            report=installer.preflight()
        self.assertEqual((report['distribution'],report['version']),('ubuntu','26.04'))
        self.assertFalse(report['firewall_changes']);self.assertFalse(report['route_changes'])
        self.assertEqual([c.args[0][0] for c in run.call_args_list],['ss','ip','systemctl','systemctl','nft'])

    def test_unknown_release_still_stops_before_commands(self):
        with patch.object(installer.sys,'platform','linux'),patch.object(installer.Path,'read_text',return_value='ID=ubuntu\nVERSION_ID="27.04"\n'),patch.object(installer,'run') as run:
            with self.assertRaisesRegex(ValueError,'unsupported distribution/version: ubuntu 27.04'):installer.preflight()
        run.assert_not_called()

    def test_ubuntu_2604_still_requires_system_tools(self):
        with patch.object(installer.sys,'platform','linux'),patch.object(installer.Path,'read_text',return_value='ID=ubuntu\nVERSION_ID="26.04"\n'),patch.object(installer.Path,'exists',return_value=True),patch.object(installer.shutil,'which',return_value=None),patch.object(installer,'run') as run:
            with self.assertRaisesRegex(ValueError,'missing prerequisite: systemctl'):installer.preflight()
        run.assert_not_called()

    def test_atomic_replacement_and_rollback_of_partial_install(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = tuple(str(root / str(i)) for i in range(6))
            Path(names[0]).write_bytes(b"original")
            unrelated = root / "unrelated"
            unrelated.write_bytes(b"untouched")
            marker = root / "ownership.json"
            journal_path = root / "transaction.json"
            fake = SimpleNamespace(returncode=1)
            with patch.multiple(installer, STATE=root, FILES=names, MARKER=marker, JOURNAL=journal_path), patch.object(installer, "run", return_value=fake), patch.object(installer.os, "chown", create=True):
                journal = installer.snapshot(names, {"test": True})
                for name in names:
                    installer.atomic(name, b"new")
                installer.restore(journal)
                self.assertEqual(Path(names[0]).read_bytes(), b"original")
                self.assertTrue(all(not Path(name).exists() for name in names[1:]))
                self.assertEqual(unrelated.read_bytes(), b"untouched")
                self.assertFalse(journal_path.exists())

    def test_recovery_refuses_unowned_paths(self):
        with self.assertRaisesRegex(ValueError, "journal paths"):
            installer.restore({"files": [{"path": "/etc/ssh/sshd_config"}]})

    def test_bad_checksum_rejected_before_executable_is_run(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "binary"
            path.write_bytes(b"untrusted")
            with patch.object(installer, "run") as run:
                with self.assertRaisesRegex(ValueError, "integrity"):
                    installer.content(SimpleNamespace(binary=path, sha256="0" * 64))
                run.assert_not_called()

if __name__ == "__main__":
    unittest.main()
