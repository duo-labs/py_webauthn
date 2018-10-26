# PyWebAuthn

[![PyPI](https://img.shields.io/pypi/v/webauthn.svg)](https://pypi.python.org/pypi/webauthn)
[![GitHub license](https://img.shields.io/badge/license-BSD-blue.svg)](https://raw.githubusercontent.com/duo-labs/py_webauthn/master/LICENSE)

PyWebAuthn is a Python module which can be used to handle [WebAuthn][1] registration and assertion. Currently, WebAuthn is supported in [Firefox][2], [Chrome][3], and [Edge][4].

# Installation

`pip install webauthn`

# Usage

Generating credential options, (to be passed to `navigator.credentials.create`):
```python
make_credential_options = webauthn.WebAuthnMakeCredentialOptions(
    challenge,
    rp_name,
    rp_id,
    user_id,
    username,
    display_name,
    icon_url)
```

Creating a `WebAuthnUser` object. Used during the assertion (login) process:
```python
webauthn_user = webauthn.WebAuthnUser(
    user.id,
    user.username,
    user.display_name,
    user.icon_url,
    user.credential_id,
    user.pub_key,
    user.sign_count,
    user.rp_id)
```

Generating assertion options, (to be passed to `navigator.credentials.get`):
```python
webauthn_assertion_options = webauthn.WebAuthnAssertionOptions(
    webauthn_user,
    challenge)
```

Verifying a registration response, (result of `navigator.credentials.create`):
```python
webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
    RP_ID,
    ORIGIN,
    registration_response,
    challenge,
    trust_anchor_dir,
    trusted_attestation_cert_required,
    self_attestation_permitted,
    none_attestation_permitted,
    uv_required=False)  # User Verification

try:
    webauthn_credential = webauthn_registration_response.verify()
except Exception as e:
    return jsonify({'fail': 'Registration failed. Error: {}'.format(e)})

# Create User
```

Verifying an assertion response, (result of `navigator.credentials.get`):
```python
webauthn_user = webauthn.WebAuthnUser(
    user.ukey,
    user.username,
    user.display_name,
    user.icon_url,
    user.credential_id,
    user.pub_key,
    user.sign_count,
    user.rp_id)

webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
    webauthn_user,
    assertion_response,
    challenge,
    origin,
    uv_required=False)  # User Verification

try:
    sign_count = webauthn_assertion_response.verify()
except Exception as e:
    return jsonify({'fail': 'Assertion failed. Error: {}'.format(e)})

# Update counter.
user.sign_count = sign_count
```

# Flask Demo

There is a [Flask][5] demo available in the `flask_demo` directory. Follow these steps to run the Flask web app:

1. `cd flask_demo`
2. `pip install -r requirements.txt`
3. `python create_db.py`
4. `python app.py`
5. Go to [https://localhost:5000][6] in your web browser. Try registering and logging in with a compatible U2F or WebAuthn authenticator.
6. Profit?

# Flask Demo (Docker)

To run the [Flask][5] demo with [Docker][7]:

1. Install Docker.
2. `docker-compose up -d`
3. Go to [https://localhost:5000][6] in your web browser. Try registering and logging in with a compatible U2F or WebAuthn authenticator.

# Note

Currently, PyWebAuthn does not support performing the following verifications.

* [Token Binding ID][8]
* [Authenticator Extensions][9]

[1]: https://www.w3.org/TR/webauthn/
[2]: https://www.mozilla.org/en-US/firefox/new/
[3]: https://www.google.com/chrome/
[4]: https://www.microsoft.com/en-us/windows/microsoft-edge
[5]: http://flask.pocoo.org/
[6]: https://localhost:5000
[7]: https://www.docker.com/
[8]: https://www.w3.org/TR/webauthn/#dom-collectedclientdata-tokenbindingid
[9]: https://www.w3.org/TR/webauthn/#dom-collectedclientdata-authenticatorextensions
