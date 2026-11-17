import hashlib
import hmac
import socket
import threading
import time
import unittest
from scripts.lab.path_compare import receive_datagram


class ProbeDeadlineTests(unittest.TestCase):
    def exchange(self,delay):
        key=b'k'*32;body=(1).to_bytes(8,'big')+b'n'*8+b'x'*112;payload=hmac.digest(key,body,'sha256')+body
        server=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);server.bind(('127.0.0.1',0))
        client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);client.connect(server.getsockname())
        def echo():
            data,peer=server.recvfrom(2048);server.sendto(data,peer)
        thread=threading.Thread(target=echo);thread.start()
        class DelayedReader:
            def settimeout(self,value):client.settimeout(value)
            def recv(self,size):
                data=client.recv(size);time.sleep(delay);return data
        try:
            start=time.monotonic();client.send(payload)
            return receive_datagram(DelayedReader(),payload,key,start,lambda:None),payload
        finally:thread.join(timeout=1);client.close();server.close()

    def test_real_reply_after_scheduler_delay_misses_deadline(self):
        with self.assertRaises(TimeoutError):self.exchange(.6)

    def test_prompt_real_reply_is_accepted(self):
        actual,expected=self.exchange(0);self.assertEqual(actual,expected)
