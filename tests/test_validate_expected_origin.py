from unittest import TestCase

from webauthn.helpers.validate_expected_origin import (
    InvalidExpectedOrigin,
    match_origins,
    validate_expected_origin,
)


class TestValidateExpectedOrigin(TestCase):
    def test_match_origins(self):
        """Test for combined match (exact and wildcard)."""
        expected_origin_result = [
            # exact match
            ("https://www.acme.com", "https://www.acme.com", True),
            # wildcard subdomain match
            ("https://*.acme.com", "https://pass.acme.com", True),
            # no match
            ("https://foo.acme.com", "https://bar.acme.com", False),
            # scheme mismatch
            ("https://acme.com", "http://acme.com", False),
            # port mismatch
            ("https://acme.com:8001", "https://acme.com:8000", False),
            # wildcard subdomain fails root domain match
            ("https://*.acme.com", "https://acme.com", False),
            # localhost match
            ("http://localhost", "http://localhost", True),
            # app protocol match (from spec)
            (
                "example-os:appid:204ffa1a5af110ac483f131a1bef8a841a7adb0d8d135908bbd964ed05d2653b",
                "example-os:appid:204ffa1a5af110ac483f131a1bef8a841a7adb0d8d135908bbd964ed05d2653b",
                True,
            ),
        ]
        for expected, origin, result in expected_origin_result:
            match = match_origins(expected, origin)
            self.assertEqual(match, result, "{} != {}".format(origin, expected))

    def validate_expected_origin(self):
        # test that validation handles a str or a list
        expected_origin_result = [
            # single str match
            ("https://www.acme.com", "https://www.acme.com", True),
            # list match
            ("https://www.acme.com", ["https://www.acme.com"], True),
            # list match
            (
                "https://www.example.org",
                ["https://acme.com", "https://www.acme.com"],
                True,
            ),
            # single str mismatch
            ("https://www.acme.com", "https://foo.acme.com", False),
            # list mismatch
            ("https://www.acme.com", ["https://foo.acme.com"], False),
            # empty expected origin
            ("https://www.acme.com", [], False),
            ("https://www.acme.com", "", False),
            # invalid expected origin
            ("https://www.acme.com", 99, False),
        ]
        for expected, origin, result in expected_origin_result:
            match = validate_expected_origin(expected, origin)
            self.assertEqual(match, result, "{} != {}".format(origin, expected))

    def invalidate_expected_origins(self):
        invalid_expected_origins = [
            # empty string
            (""),
            # starts with wildcard
            ("*.acme.com"),
            # ends with wildcard
            ("https://acme.*"),
            # multiple wildcards
            ("https://*.acme.*"),
            # reserved domains
            ("https://example.com"),
            ("https://example.net"),
            ("https://example.org"),
        ]
        for expected in invalid_expected_origins:
            self.assertRaises(InvalidExpectedOrigin, validate_expected_origin, expected)
