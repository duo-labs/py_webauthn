import cbor2

from .exceptions import InvalidAuthenticatorDataStructure
from .structs import AttestedCredentialData, AuthenticatorData, AuthenticatorDataFlags


def parse_authenticator_data(val: bytes) -> AuthenticatorData:
    """
    Turn `response.attestationObject.authData` into structured data
    """
    # Don't bother parsing if there aren't enough bytes for at least:
    # - rpIdHash (32 bytes)
    # - flags (1 byte)
    # - signCount (4 bytes)
    if len(val) < 37:
        raise InvalidAuthenticatorDataStructure(
            f"Authenticator data was {len(val)} bytes, expected at least 37 bytes"
        )

    pointer = 0

    rp_id_hash = val[pointer:32]
    pointer += 32

    # Cast byte to ordinal so we can use bitwise operators on it
    flags_bytes = ord(val[pointer : pointer + 1])
    pointer += 1

    sign_count = val[pointer : pointer + 4]
    pointer += 4

    # Parse flags
    flags = AuthenticatorDataFlags(
        up=flags_bytes & (1 << 0) != 0,
        uv=flags_bytes & (1 << 2) != 0,
        be=flags_bytes & (1 << 3) != 0,
        bs=flags_bytes & (1 << 4) != 0,
        at=flags_bytes & (1 << 6) != 0,
        ed=flags_bytes & (1 << 7) != 0,
    )

    # The value to return
    authenticator_data = AuthenticatorData(
        rp_id_hash=rp_id_hash,
        flags=flags,
        sign_count=int.from_bytes(sign_count, "big"),
    )

    # Parse AttestedCredentialData if present
    if flags.at is True:
        aaguid = val[pointer : pointer + 16]
        pointer += 16

        credential_id_len = int.from_bytes(val[pointer : pointer + 2], "big")
        pointer += 2

        credential_id = val[pointer : pointer + credential_id_len]
        pointer += credential_id_len

        # Load the next CBOR-encoded value
        credential_public_key = cbor2.loads(val[pointer:])
        credential_public_key_bytes = cbor2.dumps(credential_public_key)
        pointer += len(credential_public_key_bytes)

        attested_cred_data = AttestedCredentialData(
            aaguid=aaguid,
            credential_id=credential_id,
            credential_public_key=credential_public_key_bytes,
        )
        authenticator_data.attested_credential_data = attested_cred_data

    if flags.ed is True:
        extension_object = cbor2.loads(val[pointer:])
        extension_bytes = cbor2.dumps(extension_object)
        pointer += len(extension_bytes)
        authenticator_data.extensions = extension_bytes

    # We should have parsed all authenticator data by this point
    if (len(val) > pointer):
        raise InvalidAuthenticatorDataStructure(
            "Leftover bytes detected while parsing authenticator data"
        )

    return authenticator_data
