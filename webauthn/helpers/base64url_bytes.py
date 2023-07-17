from base64 import urlsafe_b64decode
from typing_extensions import Annotated

from pydantic import (
    AfterValidator,
    BeforeValidator,
    FieldValidationInfo,
    PlainSerializer,
    WithJsonSchema,
)
from pydantic_core import PydanticCustomError

from webauthn.helpers import bytes_to_base64url


def validate_base64url(value: bytes, info: FieldValidationInfo) -> bytes:

    if info.mode == "json":
        try:
            return urlsafe_b64decode(value + b"====")
        except ValueError as e:
            raise PydanticCustomError(
                "base64_decode", "Base64 decoding error: '{error}'", {"error": str(e)}
            ) from e

    return value


Base64URLBytes = Annotated[
    bytes,
    # Parse input strings as base64url encoded values. This assumes that bytes
    # values have already been base64 deocded.
    AfterValidator(validate_base64url),
    # When serializing to JSON, base64 encode the value. In Python mode we
    # don't do anything
    PlainSerializer(bytes_to_base64url, return_type=str, when_used="json"),
    # Specify the JSON schema of the field, which is a string with the base64
    # format
    WithJsonSchema({"type": "string", "format": "base64"}),
]
