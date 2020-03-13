import unittest
import base64
from flask_demo import util
import binascii
from unittest.mock import patch
import sys

class EncodingTests(unittest.TestCase):
    def test_confirm_padded(self):
        '''Ensure that generate_challenge correctly generates *padded* URL-safe base64.
        If a 32-byte challenge is requested, it will always have a single padding character,
        so we can trust that the decode will fail if padding is omitted.'''
        challenge_padded = util.generate_challenge()
        try:
            base64.urlsafe_b64decode(challenge_padded) # expects padded challenge
        except binascii.Error:
            self.fail("generate_challenge didn't produced padded base64")
    
    def test_confirm_byte_length(self):
        '''Ensure that generate_challenge produces values of the proper byte length.'''
        challenge_padded = util.generate_challenge()
        challenge_bytes = base64.urlsafe_b64decode(challenge_padded)
        self.assertEqual(len(challenge_bytes), util.CHALLENGE_DEFAULT_BYTE_LEN)

if __name__ == '__main__':
    unittest.main()