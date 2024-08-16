# Registration

WebAuthn registration ceremonies can be broken up into two operations:

1. Generate WebAuthn API options
2. Verify the WebAuthn response

Typical use of WebAuthn requires that a user account be identified at the time of registration. This can mean:

- The user has successfully logged in via username and password and is proceeding through a prompt to upgrade to using passkeys
- The user has just clicked a magic link to confirm their email address during new account creation
- A logged-in user is adding a passkey to go passwordless on their next login

Regardless of the scenario, the Relying Party should ensure they have **a strong sense of which user is logged in** before proceeding.

## Generate Options

Registration options are created using the following method:

```py
from webauthn import generate_registration_options
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier

# Simple Options
simple_registration_options = generate_registration_options(
    rp_id="example.com",
    rp_name="Example Co",
    user_name="bob",
)

# Complex Options
complex_registration_options = generate_registration_options(
    rp_id="example.com",
    rp_name="Example Co",
    user_id=bytes([1, 2, 3, 4]),
    user_name="Lee",
    attestation=AttestationConveyancePreference.DIRECT,
    authenticator_selection=AuthenticatorSelectionCriteria(
        authenticator_attachment=AuthenticatorAttachment.PLATFORM,
        resident_key=ResidentKeyRequirement.REQUIRED,
    ),
    challenge=bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
    exclude_credentials=[
        PublicKeyCredentialDescriptor(
            id=b"1234567890",
            transports=[
                AuthenticatorTransport.INTERNAL,
                AuthenticatorTransport.HYBRID,
            ]
        ),
    ],
    supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_512],
    timeout=12000,
)
```

[See the docstrings](https://github.com/duo-labs/py_webauthn/blob/2219507f483e5592ec980ec95d97a5d3563fa45b/webauthn/registration/generate_registration_options.py#L42-L69) for details about the various required and optional **kwargs**.

The output from `generate_registration_options()` can be passed into `webauthn.helpers.options_to_json()` to quickly convert them to a `str` value that can be sent to the browser as JSON.

:::{tip}
If you are using [@simplewebauthn/browser](overview.md#simplewebauthn-browser) in your front end code then you can pass...
```py
opts = options_to_json(
    generate_registration_options(**kwargs)
)
```
...directly into its `startRegistration(opts)` method.
:::

## Verify Response

Registration responses can be verified using the following method:

```py
from webauthn import (
    verify_registration_response,  # <--
    base64url_to_bytes,
)

verification = verify_registration_response(
    # Can be a `str` or `dict`
    credential={
        "id": "...",
        "rawId": "...",
        "response": {
            "attestationObject": "...",
            "clientDataJSON": "...",
            "transports": ["internal"],
        },
        "type": "public-key",
        "clientExtensionResults": {},
        "authenticatorAttachment": "platform",
    },
    # The value of `options.challenge` from above
    expected_challenge=base64url_to_bytes("..."),
    expected_rp_id="example.com",
    expected_origin="https://example.com",
    require_user_verification=True,
)
```

[See the docstrings](https://github.com/duo-labs/py_webauthn/blob/2219507f483e5592ec980ec95d97a5d3563fa45b/webauthn/registration/verify_registration_response.py#L67-L100) for details about the various required and optional **kwargs**.

:::{tip}
If you are using [@simplewebauthn/browser](overview.md#simplewebauthn-browser) in your front end code then you can pass the output from `startRegistration(opts)` directly into `verify_registration_response(**kwargs)` as the `credential` kwarg.
:::

After verifying a response, **store the following values** from `verification` above for the logged-in user in the database so that they can use this passkey later to sign in:

- `verification.credential_id`
- `verification.credential_public_key`
- `verification.sign_count`
- `verification.credential_device_type`
- `verification.credential_backed_up`
- `credential["response"]["transports"]`
