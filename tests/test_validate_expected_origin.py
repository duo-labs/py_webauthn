from unittest import TestCase

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
            # wildcard subdomain match
            ("https://*.example.org", "https://pass.example.org", True),
            # wildcard prefix-only match
            ("example-os*", "example-os:appid:204ffa1a5af110ac483f131a1bef8a841a7a", True),
            # wildcard suffix-only match
            ("*.com", "https://something-random.com", True),
            # wildcard match anything - this is a bad idea
            ("*", "totally random origin that isn't even an origin", True),
            # no match
            ("https://foo.example.org", "https://bar.example.org", False),
            # scheme mismatch
            ("https://example.org", "http://example.org", False),
            # port mismatch
            ("https://example.org:8001", "https://example.org:8000", False),
            # wildcard subdomain fails root domain match
            ("https://*.example.org", "https://example.org", False),
            # invalid expected origin
            ("https://*.*.example.org", "https://foo.bar.example.org", False),
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
            # empty expected origin
            ("https://www.example.org", [], False),
            ("https://www.example.org", "", False),
            # invalid expected origin
            ("https://www.example.org", 99, False),
        ]
        for expected, origin, result in expected_origin_result:
            match = validate_expected_origin(expected, origin)
            self.assertEqual(match, result, "{} != {}".format(origin, expected))
