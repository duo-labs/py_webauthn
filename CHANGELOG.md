# Changelog

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
