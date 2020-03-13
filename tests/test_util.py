import unittest
import base64
from flask_demo import util
import binascii

CHALLENGE_BYTE_LENGTH = 32

class EncodingTests(unittest.TestCase):
    def test_confirm_padded(self):
        '''Ensure that generate_challenge correctly generates *padded* URL-safe base64.'''
        challenge_padded = util.generate_challenge(CHALLENGE_BYTE_LENGTH)
        try:
            base64.urlsafe_b64decode(challenge_padded) # expects padded challenge
        except binascii.Error:
            self.fail("generate_challenge didn't produced padded base64")
    
    def test_confirm_byte_length(self):
        '''Ensure that generate_challenge produces values of the proper byte length.'''
        challenge_padded = util.generate_challenge(CHALLENGE_BYTE_LENGTH)
        challenge_bytes = base64.urlsafe_b64decode(challenge_padded)
        self.assertEqual(len(challenge_bytes), CHALLENGE_BYTE_LENGTH)

if __name__ == '__main__':
    unittest.main()