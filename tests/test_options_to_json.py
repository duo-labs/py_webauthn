import json
from unittest import TestCase

from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.options_to_json import options_to_json
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
)
from webauthn import generate_registration_options


class TestWebAuthnOptionsToJSON(TestCase):
    def test_converts_options_to_JSON(self) -> None:
        options = generate_registration_options(
            rp_id="example.com",
            rp_name="Example Co",
            user_id="ABAV6QWPBEY9WOTOA1A4",
            user_name="lee",
            user_display_name="Lee",
            attestation=AttestationConveyancePreference.DIRECT,
            authenticator_selection=AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                resident_key=ResidentKeyRequirement.REQUIRED,
            ),
            challenge=b"1234567890",
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=b"1234567890"),
            ],
            supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_512],
            timeout=120000,
        )

        output = options_to_json(options)

        assert json.loads(output) == {
            "rp": {"name": "Example Co", "id": "example.com"},
            "user": {
                "id": "QUJBVjZRV1BCRVk5V09UT0ExQTQ",
                "name": "lee",
                "displayName": "Lee",
            },
            "challenge": "MTIzNDU2Nzg5MA",
            "pubKeyCredParams": [{"type": "public-key", "alg": -36}],
            "timeout": 120000,
            "excludeCredentials": [{"type": "public-key", "id": "MTIzNDU2Nzg5MA"}],
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "residentKey": "required",
                "requireResidentKey": True,
                "userVerification": "preferred",
            },
            "attestation": "direct",
        }

    def test_includes_optional_value_when_set(self) -> None:
        options = generate_registration_options(
            rp_id="example.com",
            rp_name="Example Co",
            user_id="ABAV6QWPBEY9WOTOA1A4",
            user_name="lee",
            exclude_credentials=[
                PublicKeyCredentialDescriptor(
                    id=b"1234567890",
                    transports=[AuthenticatorTransport.USB],
                )
            ],
        )

        output = options_to_json(options)

        assert json.loads(output)["excludeCredentials"] == [
            {
                "id": "MTIzNDU2Nzg5MA",
                "transports": ["usb"],
                "type": "public-key",
            }
        ]
