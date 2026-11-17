import base64,contextlib,io,time,unittest
from unittest import mock
from scripts import code_install as pairing

class CodePairingTests(unittest.TestCase):
    def offer(self):
        return dict(pair='a'*32,listener='192.0.2.1',peer='192.0.2.2',expires=int(time.time())+3600,secret='c'*64,public_key=base64.b64encode(b'a'*32).decode(),client=dict(server='192.0.2.1',uuid='67e34514-938a-453c-9b59-b0c701199357',server_name='tls.example.org',public_key=base64.urlsafe_b64encode(b'b'*32).decode().rstrip('='),short_id='0123456789abcdef'))

    def test_offline_pair_exchange_exports_no_private_keys(self):
        offer=self.offer();decoded=pairing.invitation(pairing.encode('I',offer))
        key=base64.b64encode(b'c'*32).decode()
        self.assertEqual(pairing.accept_reply(decoded,pairing.reply(decoded,key)),key)
        self.assertNotIn('private',str(decoded))

    def test_wrong_pair_or_modified_reply_cannot_replace_peer_key(self):
        offer=self.offer();key=base64.b64encode(b'c'*32).decode();reply=pairing.reply(offer,key)
        for other in [{**offer,'pair':'d'*32},{**offer,'secret':'d'*64},{**offer,'expires':offer['expires']+1}]:
            with self.assertRaises(ValueError):pairing.accept_reply(other,reply)
        decoded=pairing.decode('R',reply);decoded['public_key']=base64.b64encode(b'd'*32).decode()
        with self.assertRaises(ValueError):pairing.accept_reply(offer,pairing.encode('R',decoded))

    def test_expired_oversized_damaged_and_wrong_type_codes_fail(self):
        offer=self.offer()
        for value in [{**offer,'expires':0},{**offer,'expires':int(time.time())+pairing.LIFETIME+1000},{**offer,'private_key':'forbidden'},{**offer,'client':{**offer['client'],'uuid':2}},{**offer,'listener':offer['peer']}]:
            with self.assertRaises(ValueError):pairing.invitation(pairing.encode('I',value))
        code=pairing.encode('I',offer)
        for value in ['x'*5000,code[:-1]+('1' if code[-1]!='1' else '2'),pairing.reply(offer,offer['public_key'])]:
            with self.assertRaises(ValueError):pairing.invitation(value)

    def test_bad_invitation_cannot_trigger_key_generation_or_install(self):
        node=mock.Mock()
        with self.assertRaises(ValueError):pairing.join(node,'not-a-code')
        node.prepare.assert_not_called();node.configure.assert_not_called();node.install.assert_not_called()

    def test_console_dependencies_do_not_require_or_install_ssh(self):
        with mock.patch('scripts.easy_install.shutil.which',side_effect=lambda tool:None if tool=='ssh' else '/usr/bin/'+tool),mock.patch('scripts.easy_install.Path.is_file',return_value=True),mock.patch('scripts.easy_install.subprocess.run') as command:
            pairing.dependencies(require_ssh=False)
        command.assert_not_called()

    def test_existing_pair_refuses_other_pair_without_changes(self):
        offer=self.offer();node=mock.Mock()
        with mock.patch.object(pairing,'read_ticket',return_value={'role':'initiator','offer':{**offer,'pair':'d'*32}}):
            with self.assertRaises(ValueError):pairing.join(node,pairing.encode('I',offer))
        node.prepare.assert_not_called();node.configure.assert_not_called()

    def test_renewed_invitation_preserves_pair_and_existing_identity(self):
        offer=self.offer();node=mock.Mock();renewed={**offer,'secret':'e'*64,'expires':offer['expires']+1}
        with mock.patch.object(pairing,'read_ticket',return_value={'role':'initiator','offer':offer}),mock.patch.object(pairing,'write_json'):
            result=pairing.join(node,pairing.encode('I',renewed))
        self.assertEqual(result['offer'],renewed)
        self.assertEqual(node.prepare.call_args.kwargs,{})
        self.assertEqual(node.prepare.call_args.args[0]['pair_id'],offer['pair'])
        self.assertEqual(node.configure.call_args.args[0]['peer_public_key'],offer['public_key'])

    def test_pending_peer_does_not_uninstall_working_local_side(self):
        node=mock.Mock();node.probe.return_value={'healthy':False,'checks':{'ipv4':False}}
        with contextlib.redirect_stdout(io.StringIO()) as out:pairing.install_local(node)
        node.install.assert_called_once();node.overlays.assert_called_once();node.rollback.assert_not_called()
        self.assertIn('not yet confirmed',out.getvalue())

    def test_failed_local_install_rolls_back_only_current_attempt(self):
        node=mock.Mock();node.overlays.side_effect=ValueError('test failure')
        with self.assertRaises(ValueError):pairing.install_local(node)
        self.assertEqual(node.install.call_args,node.rollback.call_args)
        node.probe.assert_not_called()

if __name__=='__main__':unittest.main()
