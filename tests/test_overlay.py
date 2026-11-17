import unittest
from scripts.overlay import validate

class OverlayValidationTests(unittest.TestCase):
 def config(self):return dict(name='ngo-gre',namespace='ngt-site-main',kind='gre',local='10.77.240.1',remote='10.77.240.2',address='10.78.250.1/30',mtu=1200)
 def test_valid_gre_and_vxlan(self):
  c=self.config();self.assertEqual(validate(c),c)
  self.assertEqual(validate({**c,'kind':'ipip'})['kind'],'ipip')
  c.update(kind='vxlan',vni=10771,port=4789);self.assertEqual(validate(c),c)
 def test_reject_public_endpoint_and_overlap(self):
  for patch in [dict(remote='8.8.8.8'),dict(address='10.77.240.1/30'),dict(address='10.78.250.0/30'),dict(mtu=128.0),dict(name='eth0'),dict(namespace='default'),dict(vni=1),dict(kind='vxlan',vni=0,port=4789)]:
   with self.subTest(patch=patch),self.assertRaises(ValueError):validate({**self.config(),**patch})
if __name__=='__main__':unittest.main()
