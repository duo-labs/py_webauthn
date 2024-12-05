# Changelog

## v2.4.0

**Changes:**

- An optional `hints` argument has been added to `generate_registration_options()` to specify one or more categories of authenticators for the browser to prioritize registration of. See `webauthn.helpers.structs.PublicKeyCredentialHint` for more information ([#234](https://github.com/duo-labs/py_webauthn/pull/234))

## v2.3.0

**Changes:**

- The minimum supported version of Python has been bumped up to Python 3.9, with ongoing testing from Python 3.9 through Python 3.13. Dependencies have been updated as well, including upgrading to `cryptography==43.0.3` ([#233](https://github.com/duo-labs/py_webauthn/pull/233), with thanks to @ds-cbo)

## v2.2.0

**Changes:**

- All exceptions in `webauthn.helpers.exceptions` now subclass the new `webauthn.helpers.exceptions.WebAuthnException` base exception ([#219](https://github.com/duo-labs/py_webauthn/issues/219), h/t @bschoenmaeckers)
- Support has been added for the new `"smart-card"` transport ([#221](https://github.com/duo-labs/py_webauthn/pull/221))

## v2.1.0

**Changes:**

- New `webauthn.helpers.parse_registration_options_json()` and `webauthn.helpers.parse_authentication_options_json()` methods have been added to help replace use of Pydantic's `.parse_obj()` on this library's `PublicKeyCredentialCreationOptions` and `PublicKeyCredentialRequestOptions` classes in projects upgrading to `webauthn>=2.0.0`. See **Refactor Guidance** below for more info ([#210](https://github.com/duo-labs/py_webauthn/issues/210))
- Updated dependencies to `cryptography==42.0.5` ([#212](https://github.com/duo-labs/py_webauthn/pull/212))

### Refactor Guidance

Taking an example from registration: imagine **a py_webauthn v1.11.1 scenario** in which a project using this library wanted to retrieve output from `generate_registration_options()`, serialized to JSON using `webauthn.helpers.options_to_json()` and then stored in a cache or DB, and turn it back into an instance of `PublicKeyCredentialCreationOptions`:

```py
# webauthn==1.11.1
json_reg_options: dict = get_stored_registration_options(session_id)
parsed_reg_options = PublicKeyCredentialCreationOptions.parse_obj(
    json_reg_options,
)
```

**py_webauthn v2.0.0+** removed use of Pydantic so `.parse_obj()` is no longer available on `PublicKeyCredentialCreationOptions`. It will become possible to refactor away this use of `.parse_obj()` with the new `webauthn.helpers.parse_registration_options_json()` in this release:

```py
# webauthn==2.1.0
from webauthn.helpers import parse_registration_options_json

json_reg_options: dict = get_stored_registration_options(session_id)
parsed_reg_options: PublicKeyCredentialCreationOptions = parse_registration_options_json(
    json_reg_options,
)
```

This same logic applies to calls to `PublicKeyCredentialRequestOptions.parse_obj()` - these calls can be replaced with the new `webauthn.helpers.parse_authentication_options_json()` in this release as well.

## v2.0.0

**Changes:**

- See **Breaking Changes** below

**Breaking Changes:**

- [Pydantic](https://docs.pydantic.dev/latest/) is no longer used by py_webauthn. If your project
  calls any Pydantic-specific methods on classes provided by py_webauthn then you will need to
  refactor those calls accordingly. Typical use of py_webauthn should not need any major refactor
  related to this change, but please see **Breaking Changes** below ([#195](https://github.com/duo-labs/py_webauthn/pull/195))
- `webauthn.helpers.generate_challenge()` now always generates 64 random bytes and no longer accepts any arguments. Refactor your existing calls to remove any arguments ([#198](https://github.com/duo-labs/py_webauthn/pull/198))
- `webauthn.helpers.exceptions.InvalidClientDataJSONStructure` has been replaced by `webauthn.helpers.exceptions.InvalidJSONStructure` ([#195](https://github.com/duo-labs/py_webauthn/pull/195))
- `webauthn.helpers.json_loads_base64url_to_bytes()` has been removed ([#195](https://github.com/duo-labs/py_webauthn/pull/195))
- The `user_id` argument passed into `generate_registration_options()` is now `Optional[bytes]`
  instead of a required `str` value. A random sequence of 64 bytes will be generated for `user_id`
  if it is `None` ([#197](https://github.com/duo-labs/py_webauthn/pull/197))
  - There are a few options available to refactor existing calls:

### Option 1: Use the `base64url_to_bytes()` helper

If you already store your WebAuthn user ID bytes as base64url-encoded strings then you can simply decode these strings to bytes using an included helper:

**Before:**
```py
options = generate_registration_options(
    # ...
    user_id: "3ZPk1HGhX_cul7z5UydfZE_vgnUYkOVshDNcvI1ILyQ",
)
```

**After:**

```py
from webauthn.helpers import bytes_to_base64url

options = generate_registration_options(
    # ...
    user_id: bytes_to_base64url("3ZPk1HGhX_cul7z5UydfZE_vgnUYkOVshDNcvI1ILyQ"),
)
```

### Option 2: Generate unique WebAuthn-specific identifiers for existing and new users

WebAuthn **strongly** encourages Relying Parties to use 64 randomized bytes for **every** user ID you pass into `navigator.credentials.create()`. This would be a second identifier used exclusively for WebAuthn that you associate along with your typical internal user ID.

py_webauthn includes a `generate_user_handle()` helper that can simplify the task of creating this special user identifier for your existing users in one go:

```py
from webauthn.helpers import generate_user_handle

# Pseudocode (imagine this is in some kind of migration script)
for user in get_all_users_in_db():
    add_webauthn_user_id_to_db_for_user(
        current_user=user.id,
        webauthn_user_id=generate_user_handle(),  # Generates 64 random bytes
    )
```

You can also use this method when creating new users to ensure that all subsequent users have a WebAuthn-specific identifier as well:

```py
from webauthn.helpers import generate_user_handle

# ...existing user onboarding logic...

# Pseudocode
create_new_user_in_db(
    # ...
    webauthn_user_id=generate_user_handle(),
)
```

Once your users are assigned their second WebAuthn-specific ID you can then pass those bytes into `generate_registration_options()` on subsequent calls:

```py
# Pseudocode
webauthn_user_id: bytes = get_webauthn_user_id_bytes_from_db(current_user.id)

options = generate_registration_options(
    # ...
    user_id=webauthn_user_id,
)
```

### Option 3: Let `generate_registration_options()` generate a user ID for you

When the `user_id` argument is omitted then a random 64-byte identifier will be generated for you:

**Before:**
```py
options = generate_registration_options(
    # ...
    user_id: "USERIDGOESHERE",
)
```

**After:**
```py
# Pseudocode
webauthn_user_id: bytes | None = get_webauthn_user_id_bytes_from_db(
    current_user=current_user.id,
)

options = generate_registration_options(
    # ...
    user_id=webauthn_user_id,
)

if webauthn_user_id is None:
    # Pseudocode
    store_webauthn_user_id_bytes_in_your_db(
        current_user=current_user.id,
        webauthn_user_id=options.user.id,  # Randomly generated 64-bytes
    )
```

### Option 4: Encode existing `str` argument to UTF-8 bytes

This technique is a quick win, but can be prone to base64url-related encoding and decoding quirks between browsers. **It is recommended you quickly follow this up with Option 2 or Option 3 above:**

**Before:**
```py
options = generate_registration_options(
    # ...
    user_id: "USERIDGOESHERE",
)
```

**After:**

```py
options = generate_registration_options(
    # ...
    user_id: "USERIDGOESHERE".encode('utf-8'),
)
```

## v1.11.1

**Changes:**

- Deprecation warnings related to `cbor2` in projects using `cbor2>=5.5.0` will no longer appear during registration and authentication response verification ([#181](https://github.com/duo-labs/py_webauthn/pull/181))

## v1.11.0

**Changes:**

- The `credential` argument in `verify_registration_response()` and `verify_authentication_response()` can now also be a stringified JSON `str` or a plain JSON `dict` version of a WebAuthn response ([#172](https://github.com/duo-labs/py_webauthn/pull/172), [#178](https://github.com/duo-labs/py_webauthn/pull/178))
- Various methods will now raise `webauthn.helpers.exceptions.InvalidCBORData` when there is a problem parsing CBOR-encoded data ([#179](https://github.com/duo-labs/py_webauthn/pull/179))
- Updated dependencies to `cbor2==5.4.6` and `cryptography==41.0.4` ([#178](https://github.com/duo-labs/py_webauthn/pull/178))

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
