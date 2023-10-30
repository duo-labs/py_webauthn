from unittest import TestCase

from webauthn.helpers.validate_expected_origin import (
    match_wildcard_origin,
    validate_expected_origin,
)


class TestValidateExpectedOrigin(TestCase):

    def  test_validate_origins(self):
        # orgin, expected_origin, result
        matches = [
            # straight match
            ("https://example.com", "https://example.com", True),
            # subdomain does not match
            ("https://www.example.com", "https://example.com", False),
            # straight match with a list
            ("https://example.com", ["https://foo.bar.com", "https://example.com"], True),
            # subdomain does not match with a list
            ("https://www.example.com", ["https://foo.bar.com", "https://example.com"], False),
            # subdomain allowed because of wildcard
            ("https://www.example.com", "https://*.example.com", True),
            # scheme mismatch
            ("http://www.example.com", "https://www.example.com", False),
        ]
        for origin, expected_origin, result in matches:
            is_match = validate_expected_origin(expected_origin, origin)
            assert is_match == result, "Expected {} to match {}".format(
                origin, expected_origin
            )

    def  test_match_origin(self):
       # Test the match_origin function handles strings and lists of strings
        matches = [
            # straight match
            ("https://example.com", "https://example.com", True),
            # straight match with a list
            ("https://example.com", ["https://foo.bar.com", "https://example.com"], True),
        ]
        for origin, expected_origin, result in matches:
            is_match = validate_expected_origin(expected_origin, origin)
            assert is_match == result, (
                "Expected {} to match {}".format(origin, expected_origin)
            )

    def test_match_wildcard_origin(self):
        matches = (
            ("https://*.example.com", "https://foo.example.com", True),
            ("https://*.example.com:8000", "https://foo.example.com:8000",True),
            # wildcard does not match if there is no subdomain
            ("https://*.example.com", "https://example.com", False),
        )
        for expected_origin, origin, result in matches:
            assert result == match_wildcard_origin(expected_origin, origin), (
                "Expected {} to match {}".format(origin, expected_origin)
            )
