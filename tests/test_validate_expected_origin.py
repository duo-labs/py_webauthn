from unittest import TestCase

from webauthn.helpers.exceptions import InvalidExpectedOrigin
from webauthn.helpers.validate_expected_origin import (
    match_origins,
    validate_expected_origin,
)


class TestValidateExpectedOrigin(TestCase):


    def test_match_origins(self):
        """Test for combined match (exact and wildcard)."""
        expected_origin_result = [
            # exact match
            ("https://www.example.org", "https://www.example.org", True),
            # wildcard match
            ("https://*.example.org", "https://pass.example.org", True),
            # global wildcard match
            ("*", "http://any-old-url", True),
            # no match
            ("https://foo.example.org", "https://bar.example.org", False),
            # subdomain passes with a port
            ("https://*.example.org:8000", "https://pass.example.org:8000", True),
            # root domain fails on wildcard match
            ("https://*.example.org", "https://example.org", False),
            # subdomain fails on scheme mismatch
            ("https://example.org", "http://example.org", False),
            # subdomain fails on port mismatch
            ("https://example.org:8001", "https://example.org:8000", False),
        ]
        for expected, origin, result in expected_origin_result:
            match = match_origins(expected, origin)
            self.assertEqual(match, result, "{} != {}".format(origin, expected))

    def validate_expected_origin(self):
        # test that validation handles a str or a list
        expected_origin_result = [
            # single str match
            ("https://www.example.org", "https://www.example.org", True),
            # list match
            ("https://www.example.org", ["https://www.example.org"], True),
            # list match
            ("https://www.example.org", ["https://example.org", "https://www.example.org"], True),
            # single str mismatch
            ("https://www.example.org", "https://foo.example.org", False),
            # list mismatch
            ("https://www.example.org", ["https://foo.example.org"], False),
        ]
        for expected, origin, result in expected_origin_result:
            match = validate_expected_origin(expected, origin)
            self.assertEqual(match, result, "{} != {}".format(origin, expected))

    def test_invalid_expected_origin(self) -> None:
        self.assertRaises(InvalidExpectedOrigin, match_origins, "**", "https://www.example.org")
