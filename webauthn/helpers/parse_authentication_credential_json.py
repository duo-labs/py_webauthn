from typing import Callable
from pydantic import ValidationError

from .exceptions import InvalidAuthenticationResponse
from .structs import PYDANTIC_V2, AuthenticationCredential


def parse_authentication_credential_json(json_val: str) -> AuthenticationCredential:
    if PYDANTIC_V2:
        parsing_method: Callable = AuthenticationCredential.model_validate_json
    else:  # assuming V1
        parsing_method = AuthenticationCredential.parse_raw

    try:
        authentication_credential = parsing_method(json_val)
    except ValidationError as exc:
        raise InvalidAuthenticationResponse(
            "Unable to parse an authentication credential from JSON data"
        ) from exc

    return authentication_credential
