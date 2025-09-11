import unittest
import sys
import os
from io import StringIO
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from dispatcher import Dispatcher
from exploit import OverflowExploit

"""
mode: binary
binary: target/bof/ch33
expected_responses: []
"""

class TestBinaryOverflowNiArg(unittest.TestCase):
    def setUp(self):
        self.exploit = OverflowExploit({
            'mode': 'binary',
            'binary': 'target/bof/ch33',
            'type_binary': 'ni',
            'type_input': 'arg',
            'verbose': False
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

        self.assertEqual(offset, 32, "Offset should be 32")

        # Reset stdout
        sys.stdout = sys.__stdout__

if __name__ == "__main__":
    unittest.main()