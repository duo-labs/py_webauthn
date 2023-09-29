import json
from typing import Callable, Union
from pydantic import ValidationError

from .exceptions import InvalidAuthenticationResponse
from .structs import PYDANTIC_V2, AuthenticationCredential


def parse_authentication_credential_json(json_val: Union[str, dict]) -> AuthenticationCredential:
    """
    Parse a JSON form of an authentication credential, as either a stringified JSON object or a
    plain dict, into an instance of AuthenticationCredential
    """
    if PYDANTIC_V2:
        parsing_method: Callable = AuthenticationCredential.model_validate_json  # type: ignore[attr-defined]
    else:  # assuming V1
        parsing_method = AuthenticationCredential.parse_raw

    if isinstance(json_val, dict):
        json_val = json.dumps(json_val)

    try:
        authentication_credential = parsing_method(json_val)
    except ValidationError as exc:
        raise InvalidAuthenticationResponse(
            "Unable to parse an authentication credential from JSON data"
        ) from exc

    return authentication_credential
