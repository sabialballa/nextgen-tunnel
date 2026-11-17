import socket
import struct
import tempfile
import unittest
from pathlib import Path
from scripts.lab.compare_summary import packets

class HeaderCaptureTests(unittest.TestCase):
    def fixture(self):
        ethernet=b'\0'*12+b'\x08\x00'
        ip=struct.pack('!BBHHHBBH4s4s',0x45,0,188,1,0,64,17,0,socket.inet_aton('192.0.2.1'),socket.inet_aton('198.51.100.2'))
        frame=ethernet+ip+struct.pack('!HHHH',40000,29401,168,0)+b'm'*32+b'x'*128
        header=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,96,1)
        return header+struct.pack('<IIII',10,250000,96,len(frame))+frame[:96]
    def test_udp_mac_and_timestamp_survive_header_only_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'capture.pcap';path.write_bytes(self.fixture());rows,start,end=packets(path)
            self.assertEqual((start,end),(10.25,10.25));self.assertEqual(len(rows),1)
            self.assertEqual(rows[0]['source'],'192.0.2.1');self.assertEqual(rows[0]['dport'],29401);self.assertEqual(rows[0]['mac'],(b'm'*32).hex())
    def test_truncated_capture_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'capture.pcap';path.write_bytes(self.fixture()[:-1])
            with self.assertRaises(ValueError):packets(path)

if __name__=='__main__':unittest.main()
