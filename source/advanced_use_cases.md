# Advanced Use Cases

## PQC Algorithm Support

py_webauthn v3.0.0+ supports use of **ML-DSA-44**, **ML-DSA-65**, and **ML-DSA-87** post-quantum cryptography algorithms. Relying Parties that wish to use these algorithms can make the following updates to their use of py_webauthn:

### Registration

First, define a list of supported public key algorithms:

```py
from webauthn.helpers.cose import COSEAlgorithmIdentifier

supported_pub_key_algs = [
    COSEAlgorithmIdentifier.ML_DSA_44,  # -48
    COSEAlgorithmIdentifier.ML_DSA_64,  # -49
    COSEAlgorithmIdentifier.ML_DSA_87,  # -50
    # The non-PQC algorithms that py_webauthn specifies by default
    COSEAlgorithmIdentifier.EDDSA,  # -8
    COSEAlgorithmIdentifier.ECDSA_SHA_256,  # -7
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,  # -257
]
```

Then, pass the list above as the `supported_pub_key_algs` kwarg when calling `generate_registration_options()` and `verify_registration_response()`:

```py
from webauthn import generate_registration_options

verification = generate_registration_options(
    # ...
    supported_pub_key_algs=supported_pub_key_algs,
)
```

```py
from webauthn import verify_registration_response

verification = verify_registration_response(
    # ...
    supported_pub_key_algs=supported_pub_key_algs,
)
```

### Authentication

No changes are needed when calling `generate_authentication_options()` or `verify_authentication_response()`.

## Passkeys

Coming Soon

## Conditional UI

Coming Soon
