# py_webauthn
[![PyPI](https://img.shields.io/pypi/v/webauthn.svg)](https://pypi.python.org/pypi/webauthn) [![GitHub license](https://img.shields.io/badge/license-BSD-blue.svg)](https://raw.githubusercontent.com/duo-labs/py_webauthn/master/LICENSE) ![Pythonic WebAuthn](https://img.shields.io/badge/Pythonic-WebAuthn-brightgreen?logo=python&logoColor=white)

A Python3 implementation of the [WebAuthn API](https://www.w3.org/TR/webauthn-2/) focused on making it easy to leverage the power of WebAuthn.

This library supports all FIDO2-compliant authenticators, including security keys, Touch ID, Face ID, Windows Hello, Android biometrics...and pretty much everything else.

## Installation

This module is available on **PyPI**:

`pip install webauthn`

## Requirements

- Python 3.8 and up

## Usage

The library exposes just a few core methods on the root `webauthn` module:

- `generate_registration_options()`
- `verify_registration_response()`
- `generate_authentication_options()`
- `verify_authentication_response()`

Two additional helper methods are also exposed:

- `options_to_json()`
- `base64url_to_bytes()`

Additional data structures are available on `webauthn.helpers.structs`. These are useful for constructing inputs to the methods above, and for type hinting. These [Pydantic-powered](https://pydantic-docs.helpmanual.io/) dataclasses provide runtime data validation to help ensure consistency in the shape of data being passed around.

### Registration

See **examples/registration.py** for practical examples of using `generate_registration_options()` and `verify_registration_response()`.

You can also run these examples with the following:

```sh
# See "Development" below for venv setup instructions
venv $> python -m examples.registration
```

### Authentication

See **examples/authentication.py** for practical examples of using `generate_authentication_options()` and `verify_authentication_response()`.

You can also run these examples with the following:

```sh
# See "Development" below for venv setup instructions
venv $> python -m examples.authentication
```

## Development

### Installation

Set up a virtual environment, and then install the project's requirements:

```sh
$> python3 -m venv venv
$> source venv/bin/activate
venv $> pip install -r requirements.txt
```

### Testing

Python's unittest module can be used to execute everything in the **tests/** directory:

```sh
venv $> python -m unittest
```
