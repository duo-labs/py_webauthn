from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .cose import COSEAlgorithmIdentifier
from .exceptions import MLDSANotSupported
from .decode_credential_public_key import DecodedMLDSAPublicKey


class MLDSAPublicKey(DecodedMLDSAPublicKey):
    """
    Something vaguely shaped like other PublicKey classes in cryptography. Going with something
    like this till the cryptography library itself supports PQC directly.
    """

    def __init__(self, decoded_public_key: DecodedMLDSAPublicKey) -> None:
        assert_ml_dsa_dependencies()

        super().__init__(
            kty=decoded_public_key.kty,
            alg=decoded_public_key.alg,
            pub=decoded_public_key.pub,
        )

    def verify(self, signature: bytes, data: bytes) -> None:
        """
        Verify the ML-DSA signature. Raises `cryptography.exceptions.InvalidSignature` to blend in.
        """
        from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

        if self.alg == COSEAlgorithmIdentifier.ML_DSA_44:
            verified = ML_DSA_44.verify(self.pub, data, signature)
        elif self.alg == COSEAlgorithmIdentifier.ML_DSA_65:
            verified = ML_DSA_65.verify(self.pub, data, signature)
        elif self.alg == COSEAlgorithmIdentifier.ML_DSA_87:
            verified = ML_DSA_87.verify(self.pub, data, signature)

        if not verified:
            raise InvalidSignature()

    def public_bytes(self, encoding: Encoding, format: PublicFormat) -> bytes:
        """
        From https://datatracker.ietf.org/doc/draft-ietf-cose-dilithium/09/:

        "The "pub" parameter is the ML-DSA public key, as described in
        Section 5.3 of FIPS-204."

        This method simply returns the bytes, with no support for other encodings or formats.
        Nothing that A) provides attestation, and B) uses PQC for public keys will use this
        method right now.
        """
        return self.pub


def assert_ml_dsa_dependencies() -> None:
    """
    Check that necessary dependencies are present for handling responses containing ML-DSA public
    keys.

    Raises:
        `webauthn.helpers.exceptions.MLDSANotSupported` if those dependencies are missing
    """
    try:
        import dilithium_py
    except Exception:
        raise MLDSANotSupported(
            "Please install https://pypi.org/project/dilithium-py to verify ML-DSA responses with py_webauthn"
        )
