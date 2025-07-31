import unittest
# from string_bug.web_none_stack_alignment import TestWebNoneStackAlignment
from string_bug.binary_none_stack_alignment import TestBinaryNoneStackAlignment

def suite():
    suite = unittest.TestSuite()
    # suite.addTest(TestWebNoneStackAlignment("FindOffsetTest"))
    # suite.addTest(TestWebNoneStackAlignment("ForgetConnectTest"))
    # suite.addTest(TestWebNoneStackAlignment("FindStackAddresses"))
    suite.addTest(TestBinaryNoneStackAlignment("FindOffsetTest"))
    return suite

if __name__ == "__main__":
    runner = unittest.TextTestRunner()
    runner.run(suite())