# Changelog

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
