# Authentication

WebAuthn authentication ceremonies can be broken up into two operations:

1. Generate WebAuthn API options
2. Verify the WebAuthn response

Upon successful completion of a WebAuthn ceremony, the Relying Party can use information provided in the authenticator's response to confirm (or even determine) which user should be logged in.

## Generate Options

Authentication options are created using the following method:

```py
from webauthn import generate_authentication_options
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

# Simple Options
simple_authentication_options = generate_authentication_options(
    rp_id="example.com",
)

# Complex Options
complex_authentication_options = generate_authentication_options(
    rp_id="example.com",
    challenge=b"1234567890",
    timeout=12000,
    allow_credentials=[PublicKeyCredentialDescriptor(
        id=b"1234567890",
    )],
    user_verification=UserVerificationRequirement.REQUIRED,
)
```

[See the docstrings](https://github.com/duo-labs/py_webauthn/blob/2219507f483e5592ec980ec95d97a5d3563fa45b/webauthn/authentication/generate_authentication_options.py#L11-L30) for details about the various required and optional **kwargs**.

The output from `generate_authentication_options()` can be passed into `webauthn.helpers.options_to_json()` to quickly convert them to a `str` value that can be sent to the browser as JSON.

:::{tip}
If you are using [@simplewebauthn/browser](overview.md#simplewebauthn-browser) in your front end code then you can pass...
```py
opts = options_to_json(
    generate_authentication_options(**kwargs)
)
```
...directly into its `startAuthentication(opts)` method.
:::

## Verify Response

Authentication responses can be verified using the following method:

```py
from webauthn import (
    verify_authentication_response,  # <--
    base64url_to_bytes,
)

verification = verify_authentication_response(
    # Demonstrating the ability to handle a stringified JSON
    # version of the WebAuthn response
    credential="""{
        "id": "...",
        "rawId": "...",
        "response": {
            "authenticatorData": "...",
            "clientDataJSON": "...",
            "signature": "...",
            "userHandle": "..."
        },
        "type": "public-key",
        "authenticatorAttachment": "cross-platform",
        "clientExtensionResults": {}
    }""",
    expected_challenge=base64url_to_bytes("..."),
    expected_rp_id="example.com",
    expected_origin="https://example.com",
    credential_public_key=base64url_to_bytes("..."),
    credential_current_sign_count=0,
    require_user_verification=True,
)
```

[See the docstrings](https://github.com/duo-labs/py_webauthn/blob/2219507f483e5592ec980ec95d97a5d3563fa45b/webauthn/authentication/verify_authentication_response.py#L46-L79) for details about the various required and optional **kwargs**.

:::{tip}
If you are using [@simplewebauthn/browser](overview.md#simplewebauthn-browser) in your front end code then you can pass the output from `startAuthentication(opts)` directly into `verify_authentication_response(**kwargs)` as the `credential` kwarg.
:::

:::{admonition} About `userHandle`
:class: note

When present, `credential["response"]["userHandle"]` can be used to determine which account to log the user in as. This value is a **base64url-encoded string** of `options.user.id` bytes [returned by `generate_registration_options()`](registration.md#generate-options)
:::

After verifying a response, **update the following values** from `verification` above for the logged-in user's credential record in the database that matches `credential["id"]`:

- `verification.new_sign_count`
- `verification.credential_device_type`
- `verification.credential_backed_up`
