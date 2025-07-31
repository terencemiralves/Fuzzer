import unittest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from dispatcher import Dispatcher
from tools.string_bug import FormatStringExploit

"""
mode: binary
binary: target/string_bug/ch14
"""

class TestBinaryNoneStackAlignment(unittest.TestCase):
    def setUp(self):
        self.dispatcher = Dispatcher({
            'mode': 'binary',
            'binary': 'target/string_bug/ch14'
            })
        
        self.exploit = FormatStringExploit(self.dispatcher, verbose=False)
        self.dispatcher.connect()
        if not self.dispatcher.is_connected():
            raise RuntimeError("Failed to connect to the binary process.")

    def FindOffsetTest(self):
        """
        Test to find the offset of the format string vulnerability.
        """
        offset = self.exploit.find_offset(max_offset=100, delay_between_request=0, connect_and_close=True, retry_on_error=True)
        print(f"Offset found: {offset}")
        print("Test completed successfully.")
        self.assertIsNotNone(offset, "Offset should not be None")
        print(f"Found offset: {offset}")
    
        
if __name__ == "__main__":
    unittest.main()