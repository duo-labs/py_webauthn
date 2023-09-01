from pydantic import ValidationError

from .exceptions import InvalidRegistrationResponse
from .structs import PYDANTIC_V2, RegistrationCredential


def parse_registration_credential_json(json_val: str) -> RegistrationCredential:
    if PYDANTIC_V2:
        parsing_method = RegistrationCredential.model_validate_json
    else:  # assuming V1
        parsing_method = RegistrationCredential.parse_raw

    try:
        registration_credential = parsing_method(json_val)
    except ValidationError as exc:
        raise InvalidRegistrationResponse(
            "Unable to parse a registration credential from JSON data"
        ) from exc

    return registration_credential
