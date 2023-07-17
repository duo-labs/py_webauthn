from unittest import TestCase

from pydantic import TypeAdapter, ValidationError

from webauthn.helpers.base64url_bytes import Base64URLBytes


class TestWebAuthnBase64URLBytes(TestCase):
    def test_validates_base64_string_to_bytes(self) -> None:
        ta = TypeAdapter(Base64URLBytes)

        json = b'"AQIDBAU"'
        python = bytes([1, 2, 3, 4, 5])

        assert ta.validate_json(json) == python
        assert ta.validate_python(python) == python

        with self.assertRaisesRegex(ValidationError, "Invalid base64-encoded string"):
            ta.validate_json('"1#$$"')

    def test_serializes_bytes_to_base64_string(self) -> None:
        ta = TypeAdapter(Base64URLBytes)

        json = b'"AQIDBAU"'
        python = bytes([1, 2, 3, 4, 5])

        assert ta.dump_json(python) == json
        assert ta.dump_python(python) == python
