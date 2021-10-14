import secrets
from typing import Optional, Tuple
from unittest import TestCase

from webauthn.helpers import parse_authenticator_data


def _generate_auth_data(
    sign_count: int = 0,
    up: bool = True,
    uv: bool = False,
    at: bool = False,
    ed: bool = False,
) -> Tuple[bytes, bytes, int, Optional[bytes], Optional[bytes], Optional[bytes]]:
    """A helper to generate auth_data

    Args:
        `sign_count`: How many times the authenticator has been used
        `up`: Whether user was present
        `uv`: Whether user was verified
        `at`: Whether attested credential data is present
        `ed`: Whether extension data is present

    Returns:
        A `tuple` comprised of the following values:
            `bytes`: Authenticator data
            `bytes`: RP ID hash
            `int`: Sign count
            `Optional[bytes]`: AAGUID
            `Optional[bytes]`: Credential ID
            `Optional[bytes]`: Credential public key
    """
    rp_id_hash = secrets.token_bytes(32)

    flags = 0b00000000
    if up is True:
        flags = flags | 1 << 0
    if uv is True:
        flags = flags | 1 << 2
    if at is True:
        flags = flags | 1 << 6
    if ed is True:
        flags = flags | 1 << 7

    bytes_to_join = [
        rp_id_hash,
        flags.to_bytes(1, byteorder="big"),
        sign_count.to_bytes(4, byteorder="big"),
    ]

    aaguid: Optional[bytes] = None
    credential_id: Optional[bytes] = None
    credential_public_key: Optional[bytes] = None
    if at is True:
        aaguid = secrets.token_bytes(16)
        credential_id = secrets.token_bytes(32)
        credential_public_key = secrets.token_bytes(32)

        attested_data = [
            aaguid,
            len(credential_id).to_bytes(2, byteorder="big"),
            credential_id,
            credential_public_key,
        ]

        bytes_to_join += attested_data

    auth_data = b"".join(bytes_to_join)

    return (
        auth_data,
        rp_id_hash,
        sign_count,
        aaguid,
        credential_id,
        credential_public_key,
    )


class TestWebAuthnParseAuthenticatorData(TestCase):
    def test_correctly_parses_simple(self) -> None:
        (auth_data, rp_id_hash, sign_count, _, _, _) = _generate_auth_data(
            10, up=True, uv=True
        )

        output = parse_authenticator_data(auth_data)

        assert output.rp_id_hash == rp_id_hash
        assert output.flags.up is True
        assert output.flags.uv is True
        assert output.flags.at is False
        assert output.flags.ed is False
        assert output.sign_count == sign_count

    def test_correctly_parses_attested_credential_data(self) -> None:
        (
            auth_data,
            _,
            _,
            aaguid,
            credential_id,
            credential_public_key,
        ) = _generate_auth_data(10, up=True, uv=True, at=True)

        output = parse_authenticator_data(auth_data)

        cred_data = output.attested_credential_data
        assert cred_data
        assert cred_data.aaguid == aaguid
        assert cred_data.credential_id == credential_id
        assert cred_data.credential_public_key == credential_public_key

    def test_parses_uv_false(self) -> None:
        auth_data = _generate_auth_data()[0]

        output = parse_authenticator_data(auth_data)

        assert output.flags.up is True
        assert output.flags.uv is False
