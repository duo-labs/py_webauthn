from unittest import TestCase
from unittest.mock import MagicMock, patch

from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
)
from webauthn import generate_registration_options


class TestGenerateRegistrationOptions(TestCase):
    @patch("secrets.token_bytes")
    def test_generates_options_with_defaults(self, token_bytes_mock: MagicMock) -> None:
        token_bytes_mock.return_value = b"12345"

        options = generate_registration_options(
            rp_id="example.com",
            rp_name="Example Co",
            user_id="ABAV6QWPBEY9WOTOA1A4",
            user_name="lee",
        )

        assert options.rp == PublicKeyCredentialRpEntity(
            id="example.com",
            name="Example Co",
        )
        assert options.challenge == b"12345"
        assert options.user == PublicKeyCredentialUserEntity(
            id=b"ABAV6QWPBEY9WOTOA1A4",
            name="lee",
            display_name="lee",
        )
        assert options.pub_key_cred_params[0] == PublicKeyCredentialParameters(
            type="public-key",
            alg=COSEAlgorithmIdentifier.ECDSA_SHA_256,
        )
        assert options.timeout == 60000
        assert options.exclude_credentials == []
        assert options.authenticator_selection is None
        assert options.attestation == AttestationConveyancePreference.NONE

    def test_generates_options_with_custom_values(self) -> None:
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

        assert options.rp == PublicKeyCredentialRpEntity(
            id="example.com", name="Example Co"
        )
        assert options.challenge == b"1234567890"
        assert options.user == PublicKeyCredentialUserEntity(
            id=b"ABAV6QWPBEY9WOTOA1A4",
            name="lee",
            display_name="Lee",
        )
        assert options.pub_key_cred_params[0] == PublicKeyCredentialParameters(
            type="public-key",
            alg=COSEAlgorithmIdentifier.ECDSA_SHA_512,
        )
        assert options.timeout == 120000
        assert options.exclude_credentials == [
            PublicKeyCredentialDescriptor(id=b"1234567890")
        ]
        assert options.authenticator_selection == AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            resident_key=ResidentKeyRequirement.REQUIRED,
            require_resident_key=True,
        )
        assert options.attestation == AttestationConveyancePreference.DIRECT
