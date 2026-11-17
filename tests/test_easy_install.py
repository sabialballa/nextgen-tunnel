import base64,contextlib,hashlib,io,tarfile,tempfile,unittest
from pathlib import Path
from unittest import mock
from scripts import easy_install,easy_node,menu

class EasyInstallTests(unittest.TestCase):
    def export(self):return dict(server='10.200.0.1',uuid='1a0fd68b-d742-4a29-99c7-d7de7fab81e1',server_name='tls.example.org',public_key=base64.urlsafe_b64encode(b'p'*32).decode().rstrip('='),short_id='aabbccddeeff0011')

    def test_export_is_bounded_and_cannot_disable_tls_or_redirect(self):
        e=self.export();cfg=easy_node.client_export(e,'10.200.0.1')
        self.assertTrue(cfg['tls']['enabled']);self.assertNotIn('insecure',cfg['tls'])
        for bad in [{**e,'private_key':'forbidden'},{**e,'server':'10.200.0.2'},{**e,'short_id':'bad'},{**e,'public_key':'bad'}]:
            with self.subTest(bad=set(bad)),self.assertRaises(ValueError):easy_node.client_export(bad,'10.200.0.1')

    def test_roles_generate_complementary_private_sites(self):
        key=base64.b64encode(b'p'*32).decode()
        listener=easy_node.site_config('listener',Path('/private/wg.key'),key);client=easy_node.site_config('initiator',Path('/private/wg.key'),key)
        self.assertNotIn('endpoint',listener);self.assertEqual(client['endpoint'],'127.0.0.1:51811')
        self.assertEqual(listener['remote_routes'][0],client['addresses'][0].split('/')[0]+'/32')
        self.assertTrue(all('0.0.0.0/0' not in cfg['remote_routes'] for cfg in [listener,client]))

    def test_pair_id_same_from_either_side_and_self_is_rejected(self):
        a={'host_id':'a'*64};b={'host_id':'b'*64}
        self.assertEqual(easy_install.pair_identity(a,b,'listener'),easy_install.pair_identity(b,a,'initiator'))
        with self.assertRaises(ValueError):easy_install.pair_identity(a,a,'listener')

    def test_user_configuration_only_asks_role_and_peer_ip(self):
        ask=mock.Mock(side_effect=['1','203.0.113.2']);ui=menu.Menu(ask=ask)
        with mock.patch.object(ui,'root_required'),mock.patch('scripts.easy_install.install_pair') as install,contextlib.redirect_stdout(io.StringIO()):ui.easy()
        self.assertEqual(ask.call_count,2);install.assert_called_once_with('listener','203.0.113.2',ui.root)

    def test_source_copy_cannot_contain_keys_or_private_state(self):
        raw=easy_install.source_archive(easy_install.ROOT)
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as archive:
            for member in archive:
                path=Path(member.name);self.assertTrue(member.isfile());self.assertIn(path.parts[0],['scripts','systemd']);self.assertNotIn(path.suffix,['.key','.pem','.crt']);self.assertNotIn('.private',path.parts)

    def test_existing_installation_does_not_restart_or_generate_keys(self):
        node=easy_node.Node.__new__(easy_node.Node);state={'phase':'ready','created_attempt':'old'}
        with mock.patch.object(node,'state',return_value=state),mock.patch.object(node,'verify_files'),mock.patch.object(node,'owned_native',return_value=True),mock.patch.object(node,'save'),mock.patch.object(node,'command') as command:
            self.assertTrue(node.install({'attempt':'new'})['unchanged']);command.assert_not_called()

    def test_rollback_preserves_installation_from_other_attempt(self):
        node=easy_node.Node.__new__(easy_node.Node)
        with mock.patch.object(node,'state',return_value={'created_attempt':'old','overlay_attempts':{}}),mock.patch.object(node,'command') as command:
            result=node.rollback({'attempt':'new'});self.assertTrue(result['existing_installation_preserved']);command.assert_not_called()

    def test_modified_generated_file_is_not_replaced(self):
        node=easy_node.Node.__new__(easy_node.Node)
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'private.key';path.write_bytes(b'changed')
            with self.assertRaises(ValueError):node.verify_files({'files':{str(path):hashlib.sha256(b'original').hexdigest()}})

if __name__=='__main__':unittest.main()
