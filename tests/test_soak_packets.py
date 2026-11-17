import struct
import unittest
from scripts.lab.stack_soak import classify_udp

class SoakPacketTests(unittest.TestCase):
    def test_delayed_valid_response_is_not_corruption(self):
        body=b'nonce123'+b'x'*144
        self.assertEqual(classify_udp(struct.pack('!Q',7)+body,struct.pack('!Q',8)+body),'late')

    def test_current_and_foreign_responses(self):
        packet=struct.pack('!Q',8)+b'nonce123'+b'x'*144
        self.assertEqual(classify_udp(packet,packet),'current')
        self.assertEqual(classify_udp(packet[:-1]+b'z',packet),'invalid')
        self.assertEqual(classify_udp(packet[:8]+b'foreign!'+packet[16:],packet),'invalid')
