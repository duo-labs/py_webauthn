# Overview

The **py_webauthn** library exposes a small number of core methods from the `webauthn` module:

- `generate_registration_options()`
- `verify_registration_response()`
- `generate_authentication_options()`
- `verify_authentication_response()`

Two additional helper methods are also exposed:

- `options_to_json()`
- `base64url_to_bytes()`

Additional data structures are available on `webauthn.helpers.structs`. These dataclasses are useful for constructing inputs to the methods above, and for providing type hinting to help ensure consistency in the shape of data being passed around.

## Assumptions

The library makes the following assumptions about how a Relying Party that is incorporating this library into their project will interface with the WebAuthn API:

- **JSON** is the preferred data type for transmitting WebAuthn API options from the **server** to the **browser**.
- **JSON** is the preferred data type for transmitting WebAuthn responses from the **browser** to the **server**.
- Bytes are not directly transmittable in either direction as JSON, and so should be encoded to and decoded from **base64url** to avoid introducing any more dependencies than those that [are specified in the WebAuthn spec](https://www.w3.org/TR/webauthn-2/#sctn-dependencies).

## Front End Libraries

py_webauthn is concerned exclusively with the **server** side of supporting WebAuthn. This means that Relying Parties will need to orchestrate calls to WebAuthn in the **browser** in some other way.

Typically this means **manually writing front end JavaScript** to coordinate encoding and decoding certain **bytes** values to and from **base64url** before calling WebAuthn's `navigator.credentials.create()` and `navigator.credentials.get()`.

Relying Parties may also consider **using an existing third-party library** that takes care of all this.

### @simplewebauthn/browser

A great third-party library option is the **@simplewebauthn/browser** library out of the SimpleWebAuthn project:

<https://simplewebauthn.dev/docs/packages/browser>

The methods available in **@simplewebauthn/browser** can accept JSON output from this project without modification, and their return values can be passed as-is into the `credential` argument of this library's response verification methods. See the SimpleWebAuthn docs for more information.
