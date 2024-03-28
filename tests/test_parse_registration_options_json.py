from unittest import TestCase

from webauthn.helpers import base64url_to_bytes, options_to_json
from webauthn.helpers.exceptions import InvalidJSONStructure, InvalidRegistrationResponse
from webauthn.helpers.structs import (
    AuthenticatorTransport,
    AuthenticatorAttachment,
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    UserVerificationRequirement,
    PublicKeyCredentialParameters,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.parse_registration_options_json import parse_registration_options_json
from webauthn.registration.generate_registration_options import generate_registration_options


class TestParseRegistrationOptionsJSON(TestCase):
    maxDiff = None

    def test_raises_on_non_dict_json(self) -> None:
        with self.assertRaisesRegex(InvalidJSONStructure, "not a JSON object"):
            parse_registration_options_json("[0]")

    def test_returns_parsed_options_simple(self) -> None:
        parsed = parse_registration_options_json(
            {
                "rp": {"name": "Example Co", "id": "example.com"},
                "user": {
                    "id": "vEC5nFXSxpc_W68bX59JeD3c_-1XDJ5RblcWjY3Tx7RvfC0rkB19UWadf6wDEWG8T1ztksOYMim0sJIn6z_5tw",
                    "name": "bob",
                    "displayName": "bob",
                },
                "challenge": "scb_z5GweYijAT2ppsB0HAklsw96fPs_tOWh-myqkOeb9rcvhWBwUZ56J3t3eocgjHkS4Mf3XeXTOQc1ySvk5w",
                "pubKeyCredParams": [
                    {"type": "public-key", "alg": -7},
                    {"type": "public-key", "alg": -8},
                    {"type": "public-key", "alg": -36},
                    {"type": "public-key", "alg": -37},
                    {"type": "public-key", "alg": -38},
                    {"type": "public-key", "alg": -39},
                    {"type": "public-key", "alg": -257},
                    {"type": "public-key", "alg": -258},
                    {"type": "public-key", "alg": -259},
                ],
                "timeout": 60000,
                "excludeCredentials": [],
                "attestation": "none",
            }
        )

        self.assertEqual(
            parsed.rp, PublicKeyCredentialRpEntity(id="example.com", name="Example Co")
        )
        self.assertEqual(
            parsed.user,
            PublicKeyCredentialUserEntity(
                id=base64url_to_bytes(
                    "vEC5nFXSxpc_W68bX59JeD3c_-1XDJ5RblcWjY3Tx7RvfC0rkB19UWadf6wDEWG8T1ztksOYMim0sJIn6z_5tw"
                ),
                name="bob",
                display_name="bob",
            ),
        )
        self.assertEqual(parsed.attestation, AttestationConveyancePreference.NONE)
        self.assertEqual(parsed.authenticator_selection, None)
        self.assertEqual(
            parsed.challenge,
            base64url_to_bytes(
                "scb_z5GweYijAT2ppsB0HAklsw96fPs_tOWh-myqkOeb9rcvhWBwUZ56J3t3eocgjHkS4Mf3XeXTOQc1ySvk5w"
            ),
        )
        self.assertEqual(parsed.exclude_credentials, [])
        self.assertEqual(
            parsed.pub_key_cred_params,
            [
                PublicKeyCredentialParameters(
                    alg=COSEAlgorithmIdentifier.ECDSA_SHA_256,
                    type="public-key",
                ),
                PublicKeyCredentialParameters(
                    alg=COSEAlgorithmIdentifier.EDDSA,
                    type="public-key",
                ),
                PublicKeyCredentialParameters(
                    alg=COSEAlgorithmIdentifier.ECDSA_SHA_512,
                    type="public-key",
                ),
                PublicKeyCredentialParameters(
                    alg=COSEAlgorithmIdentifier.RSASSA_PSS_SHA_256,
                    type="public-key",
                ),
                PublicKeyCredentialParameters(
                    alg=COSEAlgorithmIdentifier.RSASSA_PSS_SHA_384,
                    type="public-key",
                ),
                PublicKeyCredentialParameters(
                    alg=COSEAlgorithmIdentifier.RSASSA_PSS_SHA_512,
                    type="public-key",
                ),
                PublicKeyCredentialParameters(
                    alg=COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
                    type="public-key",
                ),
                PublicKeyCredentialParameters(
                    alg=COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_384,
                    type="public-key",
                ),
                PublicKeyCredentialParameters(
                    alg=COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_512,
                    type="public-key",
                ),
            ],
        )
        self.assertEqual(parsed.timeout, 60000)

    def test_returns_parsed_options_full(self) -> None:
        parsed = parse_registration_options_json(
            {
                "rp": {"name": "Example Co", "id": "example.com"},
                "user": {"id": "AQIDBA", "name": "lee", "displayName": "Lee"},
                "challenge": "AQIDBAUGBwgJAA",
                "pubKeyCredParams": [{"type": "public-key", "alg": -36}],
                "timeout": 12000,
                "excludeCredentials": [
                    {
                        "id": "MTIzNDU2Nzg5MA",
                        "type": "public-key",
                        "transports": ["internal", "hybrid"],
                    }
                ],
                "authenticatorSelection": {
                    "authenticatorAttachment": "platform",
                    "residentKey": "required",
                    "requireResidentKey": True,
                    "userVerification": "discouraged",
                },
                "attestation": "direct",
            }
        )

        self.assertEqual(
            parsed.rp, PublicKeyCredentialRpEntity(id="example.com", name="Example Co")
        )
        self.assertEqual(
            parsed.user,
            PublicKeyCredentialUserEntity(
                id=base64url_to_bytes("AQIDBA"),
                name="lee",
                display_name="Lee",
            ),
        )
        self.assertEqual(parsed.attestation, AttestationConveyancePreference.DIRECT)
        self.assertEqual(
            parsed.authenticator_selection,
            AuthenticatorSelectionCriteria(
                authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                resident_key=ResidentKeyRequirement.REQUIRED,
                require_resident_key=True,
                user_verification=UserVerificationRequirement.DISCOURAGED,
            ),
        )
        self.assertEqual(parsed.challenge, base64url_to_bytes("AQIDBAUGBwgJAA"))
        self.assertEqual(
            parsed.exclude_credentials,
            [
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes("MTIzNDU2Nzg5MA"),
                    transports=[AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID],
                )
            ],
        )
        self.assertEqual(
            parsed.pub_key_cred_params,
            [
                PublicKeyCredentialParameters(
                    alg=COSEAlgorithmIdentifier.ECDSA_SHA_512,
                    type="public-key",
                )
            ],
        )
        self.assertEqual(parsed.timeout, 12000)
