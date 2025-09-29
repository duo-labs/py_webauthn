from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .cose import COSEAlgorithmIdentifier
from .exceptions import PQCNotSupported
from .decode_credential_public_key import DecodedMLDSAPublicKey


class MLDSAPublicKey(DecodedMLDSAPublicKey):
    """
    Something vaguely shaped like other PublicKey classes in cryptography. Going with something
    like this till the cryptography library itself supports PQC directly.
    """

    def __init__(self, decoded_public_key: DecodedMLDSAPublicKey) -> None:
        try:
            import dilithium_py
        except Exception:
            raise PQCNotSupported()

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
        return self.pub
