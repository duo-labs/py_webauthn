from .cose import COSEAlgorithmIdentifier

class ML_DSAPublicKey:
    def __init__(self, alg, pub) -> None:
        if not isML_DSA_available():
            raise Exception("OQS Not installed")
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


def isML_DSA_available():
    try:
        import oqs
        return True
    except Exception as e:
        return False