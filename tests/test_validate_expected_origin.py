from unittest import TestCase

from webauthn.helpers.validate_expected_origin import validate_expected_origin


class TestValidateExpectedOrigin(TestCase):

    # orgin, expected_origin, result
    TEST_PARAMS = [
        # straight match
        ("https://example.com", "https://example.com", True),
        # straight match with a list
        ("https://example.com", ["https://foo.bar.com", "https://example.com"], True),
        # subdomain does not match
        ("https://www.example.com", "https://example.com", False),
        # subdomain does not match with a list
        ("https://www.example.com", ["https://foo.bar.com", "https://example.com"], False),
        # subdomain allowed becuase of wildcard
        ("https://www.example.com", "https://*.example.com", True),
        # subdomain allowed becuase of wildcard, no scheme in expected
        ("https://www.example.com", "*.example.com", True),
        # subdomain allowed becuase of wildcard, no scheme in expected
        ("https://www.example.com", "*.example.com", True),
        # match with port number
        ("https://example.com:8000", ["example.com:8000","example.com:8001"], True),
        # no match with port number
        ("https://example.com:8001", "example.com:8000", False),
    ]

    def  test_validate_origins(self):
        for origin, expected_origin, result in self.TEST_PARAMS:
            is_match = validate_expected_origin(expected_origin, origin)
            self.assertEqual(is_match, result)

    # TODO: add test for invalid expected_origin once we have regenerated the
    #       test data
    # def  test_invalid_origins(self):
    #     # should raise ValueError as it's not HTTPS
    #     validate_expected_origin("example.com", "example.com")
