from unittest import TestCase

from webauthn.helpers.validate_expected_origin import (
    match_root_domain,
    validate_expected_origin,
)


class TestValidateExpectedOrigin(TestCase):

    def  test_validate_origins(self):
        # orgin, expected_origin, result
        test_data = [
            # root domain match
            ("https://example.org", ["https://example.org", "https://login.example.org"], True),
            # subdomain match
            ("https://login.example.org", ["https://example.org", "https://login.example.org"], True),
            # match on non-HTTP scheme (from w3c docs)
            ("example-os:appid:204ffa", ["https://example.org", "example-os:appid:204ffa"], True),
            # subdomain not found in list
            ("https://fail.example.org", ["https://example.org", "https://login.example.org"], False),
            # subdomain fails on exact root domain main
            ("https://fail.example.org", "https://example.org", False),
            # subdomain passes on wildcard match
            ("https://fail.example.org", "https://*.example.org", True),
            # root domain failes on wildcard match
            ("https://example.org", "https://*.example.org", False),
        ]
        for origin, expected_origin, result in test_data:
            assert validate_expected_origin(expected_origin, origin) == result, (
                "Expected {} to match {}".format(origin, expected_origin)
            )

    def test_match_root_domain(self):
        test_data = [
            # subdomain passes on wildcard match
            ("https://pass.example.org", "https://*.example.org", True),
            # subdomain passes with a port
            ("https://pass.example.org:8000", "https://*.example.org:8000", True),
            # root domain fails on wildcard match
            ("https://example.org", "https://*.example.org", False),
            # subdomain fails on scheme mismatch
            ("http://fail.example.org", "https://*.example.org", False),
            # subdomain fails on port mismatch
            ("https://fail.example.org:8000", "https://*.example.org:8001", False),
        ]
        for origin, wildcard, result in test_data:
            assert match_root_domain(wildcard, origin) == result, (
                "Expected {} to match {}".format(origin, wildcard)
            )

    def test_match_root_domain__errors(self):
        # check for origins that do not support wildcards
        origins = (
            # invalid scheme
            "file://*.example.com",
            # missing wildcard
            "https://example.org",
        )
        for invalid_origin in origins:
            self.assertRaises(
                ValueError,
                match_root_domain,
                invalid_origin,
                "https://foo.example.com"
            )
