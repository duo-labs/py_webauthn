from unittest import TestCase

from webauthn.helpers.validate_expected_origin import (
    is_exact_match,
    is_wildcard_match,
    match_origins,
    validate_expected_origin,
)


class TestValidateExpectedOrigin(TestCase):

    def test_is_exact_match(self):
        """Test for case insensitive exact match."""
        expected_origin_result = [
            # exact match
            ("https://www.example.org", "https://www.example.org", True),
            # case insensitive match
            ("https://www.EXAMPLE.org", "https://www.example.org", True),
            # check subdomain fails on exact match
            ("https://example.org", "https://www.example.org", False),
        ]
        for expected, origin, result in expected_origin_result:
            match = is_exact_match(expected, origin)
            self.assertEqual(match, result, "{} != {}".format(origin, expected))

    def test_is_wildcard_match(self):
        """Test for http(s) wildcard match."""
        expected_origin_result = [
            # subdomain passes on wildcard match
            ("https://*.example.org", "https://pass.example.org", True),
            # subdomain passes with a port
            ("https://*.example.org:8000", "https://pass.example.org:8000", True),
            # root domain fails on wildcard match
            ("https://*.example.org", "https://example.org", False),
            # subdomain fails on scheme mismatch
            ("https://*.example.org", "http://fail.example.org", False),
            # subdomain fails on port mismatch
            ("https://*.example.org:8001", "https://fail.example.org:8000", False),
            ("https://*.example.org", "https://fail.example.org:80", False),
            ("https://*.example.org:80", "https://fail.example.org", False),
            # unsupported scheme
            ("file://path/to/*/example.org", "file://path/to/*/example.org", False),
            # unsupported scheme
            ("file://path/to/*/example.org", "file://path/to/*/example.org", False),
            # not a wildcard - exact match
            ("https://example.org", "https://example.org", True),
        ]
        for expected, origin, result in expected_origin_result:
            match = is_wildcard_match(expected, origin)
            self.assertEqual(match, result, "{} != {}".format(origin, expected))

    def test_match_origins(self):
        """Test for combined match (exact and wildcard)."""
        expected_origin_result = [
            # exact match
            ("https://www.example.org", "https://www.example.org", True),
            # wildcard match
            ("https://*.example.org", "https://pass.example.org", True),
            # no match
            ("https://foo.example.org", "https://bar.example.org", False),
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
