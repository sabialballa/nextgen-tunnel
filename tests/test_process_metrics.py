import os
import sys
import unittest
from scripts.process_metrics import sample

class ProcessMetricsTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt" or sys.platform == "linux", "supported sampling platforms")
    def test_own_process_cpu_and_rss_are_real_nonnegative_values(self):
        value = sample(os.getpid())
        self.assertGreaterEqual(value["cpu_seconds"], 0)
        self.assertGreater(value["rss_bytes"], 0)

if __name__ == "__main__": unittest.main()
