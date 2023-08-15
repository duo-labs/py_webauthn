# Changelog

## v1.10.1

**Changes:**

- Fix parsing error caused by registration responses from certain models of authenticators that incorrectly CBOR-encode their `authData` after creating an Ed25519 public keys ([#167](https://github.com/duo-labs/py_webauthn/pull/167))

## v1.10.0

**Changes:**

- Support use in projects using either Pydantic v1 or v2 ([#166](https://github.com/duo-labs/py_webauthn/pull/166))

## v1.9.0

**Changes:**

- Keep using Pydantic v1.x for now ([#157](https://github.com/duo-labs/py_webauthn/pull/157))
- Update cryptography and pyOpenSSL dependencies ([#154](https://github.com/duo-labs/py_webauthn/pull/154), [#158](https://github.com/duo-labs/py_webauthn/pull/158))

## v1.8.1

**Changes:**

- Update dependency versions in **setup.py** ([#151](https://github.com/duo-labs/py_webauthn/pull/151))

## v1.8.0

**Changes:**

- Move the `RegistrationCredential.transports` property into `RegistrationCredential.response.transports` to better conform to upcoming WebAuthn JSON serialization method output ([#150](https://github.com/duo-labs/py_webauthn/pull/150))

## v1.7.2

**Changes:**

- Update `cryptography` to 39.0.1 (and its dependency `pyOpenSSL` to 23.0.0) ([#148](https://github.com/duo-labs/py_webauthn/pull/148))
  - See ["39.0.1 - 2023-02-07" in cryptography's CHANGELOG](https://github.com/pyca/cryptography/blob/main/CHANGELOG.rst#3901---2023-02-07) for more info

## v1.7.1

**Changes:**

- Add support for `from webauthn import *` syntax with proper use of `__all__` ([#146](https://github.com/duo-labs/py_webauthn/pull/146))

## 1.7.0

**Changes:**

- Add new `authenticator_attachment` value to `RegistrationCredential` and `AuthenticationCredential`, defining the attachment of the authenticator that completed a corresponding ceremony, as it may be returned by the WebAuthn API ([#141](https://github.com/duo-labs/py_webauthn/pull/141))

## 1.6.0

**Changes:**

- Add new `credential_device_type` and `credential_backed_up` values to output from `verify_registration_response()` and `verify_authentication_response()` ([#136](https://github.com/duo-labs/py_webauthn/pull/136))
- Add support for the new `"hybrid"` transport (the generalized, eventual successor to `"cable"`) ([#137](https://github.com/duo-labs/py_webauthn/pull/137))

## 1.5.2

**Changes:**

- Restore the ability to pass more common bytes-like values for `bytes` fields, such as `str` values ([#132](https://github.com/duo-labs/py_webauthn/pull/132))

## 1.5.1

**Changes:**

- Refine support for bytes-like inputs to comply with stricter mypy configurations ([#130](https://github.com/duo-labs/py_webauthn/pull/130))

## 1.5.0

**Changes:**

- Fix authenticator data parsing to correctly parse extension data when present ([#125](https://github.com/duo-labs/py_webauthn/pull/125))
- Add support for the new `"cable"` transport ([#129](https://github.com/duo-labs/py_webauthn/pull/129))

## 1.4.0

**Changes:**

- Add support for `memoryviews` for `BytesLike` properties including `credential_public_key`, `authenticator_data`, etc...

## v1.3.0

**Changes:**

- Switch back from attrs + cattrs to **Pydantic** while preserving support for `bytes`-like values in subclasses of `WebAuthnBaseModel`.
  - See issue [#113](https://github.com/duo-labs/py_webauthn/issues/113) for more context

## v1.2.1

**Changes:**

- Clarify `credential` docstring for `verify_authentication_response()`


## v1.2.0

**Changes:**

- Switched from Pydantic to the combination of **attrs + cattrs**. This achieves more-Pythonic library behavior when used in a project alongside other third-party packages that use subclasses of `bytes` to represent such values as credential IDs and public keys.


## v1.1.0

**Changes:**

- Fixed SafetyNet attestation statement verification failing due to server time drift
- Added py.typed file to indicate type information is present (PEP-561)


## v1.0.1

**Changes:**

- Fixed SafetyNet unit test failing due to expired x5c certs (see PR #99)


## v1.0.0 - Like a whole new library...

This preview release of the revitalized py_webauthn library features an entirely new API, as well as support for all attestation statement formats included in L2 of the WebAuthn spec:

- **Packed**
- **TPM**
- **Android Key**
- **Android SafetyNet**
- **FIDO U2F**
- **Apple**
- **None**

Practical examples are included in the **examples/** directory to serve as a primary reference for now on how to use the new library functionality.

**Changes:**

- Everything. The entire package was replaced with a new library with a new API. Check it out :rocket:
