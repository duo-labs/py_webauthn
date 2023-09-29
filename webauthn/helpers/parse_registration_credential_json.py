import json
from typing import Callable, Union
from pydantic import ValidationError

from .exceptions import InvalidRegistrationResponse
from .structs import PYDANTIC_V2, RegistrationCredential


def parse_registration_credential_json(json_val: Union[str, dict]) -> RegistrationCredential:
    """
    Parse a JSON form of a registration credential, as either a stringified JSON object or a
    plain dict, into an instance of RegistrationCredential
    """
    if PYDANTIC_V2:
        parsing_method: Callable = RegistrationCredential.model_validate_json  # type: ignore[attr-defined]
    else:  # assuming V1
        parsing_method = RegistrationCredential.parse_raw

    if isinstance(json_val, dict):
        json_val = json.dumps(json_val)

    try:
        registration_credential = parsing_method(json_val)
    except ValidationError as exc:
        raise InvalidRegistrationResponse(
            "Unable to parse a registration credential from JSON data"
        ) from exc

    return registration_credential
