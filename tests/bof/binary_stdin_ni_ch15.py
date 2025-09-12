import unittest
import sys
import os
from io import StringIO
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from dispatcher import Dispatcher
from exploit.bof_exploit import OverflowExploit

"""
mode: binary
binary: target/bof/ch15
expected_responses: []
"""

class TestBinaryOverflowNiStdin(unittest.TestCase):
    def setUp(self):
        self.exploit = OverflowExploit({
            'mode': 'binary',
            'binary': 'target/bof/ch15',
            'type_binary': 'ni',
            'type_input': 'stdin',
            'verbose': False,
            'sendline': True
            })

    def FindOffsetTest(self):
        """
        Test to find the offset of the buffer overflow vulnerability.
        """
        # Capture the output
        captured_output = StringIO()
        sys.stdout = captured_output
        
        # Run the exploit to find the offset
        offset = self.exploit.run()

        self.assertEqual(offset, 128, "Offset should be 128")

        # Reset stdout
        sys.stdout = sys.__stdout__

if __name__ == "__main__":
    unittest.main()