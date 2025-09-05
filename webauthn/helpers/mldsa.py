from .cose import COSEAlgorithmIdentifier
from .exceptions import MldsaAttemptedWithoutInstall

class MLDSAPublicKey:
    def __init__(self, alg, pub) -> None:
        if not is_ml_dsa_available():
            raise MldsaAttemptedWithoutInstall()
        import oqs
        self.alg=alg
        self.pub=pub
        if alg==COSEAlgorithmIdentifier.ML_DSA_44:
            self.verifier=oqs.Signature('ML-DSA-44')
        if alg==COSEAlgorithmIdentifier.ML_DSA_65:
            self.verifier=oqs.Signature('ML-DSA-65')

    def verify(self, signature, data) -> None:
        import oqs
        assert self.verifier.verify(data, signature, self.pub)

_ml_dsa_available=None

def is_ml_dsa_available():
    global _ml_dsa_available
    if _ml_dsa_available is not None:
        return _ml_dsa_available
    try:
        import oqs
        _ml_dsa_available=True
    except Exception as e:
        _ml_dsa_available=False

    return _ml_dsa_available