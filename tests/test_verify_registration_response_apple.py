from unittest import TestCase
from unittest.mock import MagicMock, patch

from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.structs import AttestationFormat
from webauthn import verify_registration_response


class TestVerifyRegistrationResponseApple(TestCase):
    # TODO: Revisit these tests when we figure out how to generate dynamic certs that
    # won't start failing tests 72 hours after creation...
    @patch("OpenSSL.crypto.X509StoreContext.verify_certificate")
    def test_verify_attestation_apple_passkey(self, mock_verify_certificate: MagicMock) -> None:
        # Mocked because these certs actually expired and started failing this test
        mock_verify_certificate.return_value = True

        credential = """{
            "id": "0yhsKG_gCzynIgNbvXWkqJKL8Uc",
            "rawId": "0yhsKG_gCzynIgNbvXWkqJKL8Uc",
            "response": {
                "attestationObject": "o2NmbXRlYXBwbGVnYXR0U3RtdKFjeDVjglkCRzCCAkMwggHJoAMCAQICBgF7o5kiITAKBggqhkjOPQQDAjBIMRwwGgYDVQQDDBNBcHBsZSBXZWJBdXRobiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIxMDgzMTIzMDIwN1oXDTIxMDkwMzIzMDIwN1owgZExSTBHBgNVBAMMQGIxMGY3MThiYzVkZDc1ODg4NmExZDhjZmI1YjhiNjMxNzI5ZjRkN2U0YmEwNjlhYjBhOTkyYzFjMDg0NzhhZjkxGjAYBgNVBAsMEUFBQSBDZXJ0aWZpY2F0aW9uMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE0SSw6f-BknI8nuL6T4Fw03PgMobPiAruxwCKFM3qZHJJY-BbuMRKn5gN7RKqijN5XPgdMedBFs7W8fTF6ww1j6NVMFMwDAYDVR0TAQH_BAIwADAOBgNVHQ8BAf8EBAMCBPAwMwYJKoZIhvdjZAgCBCYwJKEiBCDkV-W8KS8WNSECSO0ud2uhKcfMRpUkp1NWg2yu8vBYoDAKBggqhkjOPQQDAgNoADBlAjBlxucHXdrLUIeahBKQR1kBPQ2nhyZAh1mgHxmUwXlaacLB0RMGwtG8l75hQWJ7hncCMQCrC559l8orYDse224mTEm_GXE4DCr6XTf4xP9aXebUV6GcuAwCsu35SwhT4EgvhoZZAjgwggI0MIIBuqADAgECAhBWJVOVx6f7QOviKNgmCFO2MAoGCCqGSM49BAMDMEsxHzAdBgNVBAMMFkFwcGxlIFdlYkF1dGhuIFJvb3QgQ0ExEzARBgNVBAoMCkFwcGxlIEluYy4xEzARBgNVBAgMCkNhbGlmb3JuaWEwHhcNMjAwMzE4MTgzODAxWhcNMzAwMzEzMDAwMDAwWjBIMRwwGgYDVQQDDBNBcHBsZSBXZWJBdXRobiBDQSAxMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgy6HLyYUkYECJbn1_Na7Y3i19V8_ywRbxzWZNHX9VJBE35v-GSEXZcaaHdoFCzjUUINAGkNPsk0RLVbD4c-_y5iR_sBpYIG--Wy8d8iN3a9Gpa7h3VFbWvqrk76cCyaRo2YwZDASBgNVHRMBAf8ECDAGAQH_AgEAMB8GA1UdIwQYMBaAFCbXZNnFeMJaZ9Gn3msS0Btj8cbXMB0GA1UdDgQWBBTrroLE_6GsW1HUzyRhBQC-Y713iDAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDaAAwZQIxAN2LGjSBpfrZ27TnZXuEHhRMJ7dbh2pBhsKxR1dQM3In7-VURX72SJUMYy5cSD5wwQIwLIpgRNwgH8_lm8NNKTDBSHhR2WDtanXx60rKvjjNJbiX0MgFvvDH94sHpXHG6A4HaGF1dGhEYXRhWJiPh6BZvowZk4E0cyGRAQ-e4LvoufWAcLD1j4UMTOIowUUAAAAA8kqOcNDT-CwpNzJSPMTeWgAU0yhsKG_gCzynIgNbvXWkqJKL8UelAQIDJiABIVgg0SSw6f-BknI8nuL6T4Fw03PgMobPiAruxwCKFM3qZHIiWCBJY-BbuMRKn5gN7RKqijN5XPgdMedBFs7W8fTF6ww1jw",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiMW5ocXlNa2ZHQVFMLXRUY3NmcHVveXE4aHFlb0hyMGQ5dERtanYxQnVKOTdZVEEzRkxXUzVFZFk0cVVnLU16cnVjMnNpQmR5VmxuRklQQjFnMEhoMkEiLCJvcmlnaW4iOiJodHRwczovL2RldjIuZG9udG5lZWRhLnB3OjUwMDAifQ"
            },
            "type": "public-key",
            "clientExtensionResults": {}
        }"""
        challenge = base64url_to_bytes(
            "1nhqyMkfGAQL-tTcsfpuoyq8hqeoHr0d9tDmjv1BuJ97YTA3FLWS5EdY4qUg-Mzruc2siBdyVlnFIPB1g0Hh2A"
        )
        rp_id = "dev2.dontneeda.pw"
        expected_origin = "https://dev2.dontneeda.pw:5000"

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=expected_origin,
            expected_rp_id=rp_id,
        )

        assert verification.fmt == AttestationFormat.APPLE
        assert verification.credential_id == base64url_to_bytes("0yhsKG_gCzynIgNbvXWkqJKL8Uc")
