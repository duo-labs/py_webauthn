from typing import Union
from pydantic import ValidationError

from .exceptions import InvalidAuthenticationResponse
from .structs import PYDANTIC_V2, AuthenticationCredential


def parse_authentication_credential(json_val: Union[str, bytes, bytearray]) -> AuthenticationCredential:
    if PYDANTIC_V2:
        parsing_method = AuthenticationCredential.model_validate_json
    else:  # assuming V1
        parsing_method = AuthenticationCredential.parse_raw

    try:
        authentication_credential = parsing_method(json_val)
    except ValidationError as exc:
        raise InvalidAuthenticationResponse(
            "Unable to parse an authentication credential from JSON data"
        ) from exc

    return authentication_credential
