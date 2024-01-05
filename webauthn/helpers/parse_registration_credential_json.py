import json
from typing import Callable, Union

from .exceptions import InvalidRegistrationResponse
from .structs import RegistrationCredential


def parse_registration_credential_json(json_val: Union[str, dict]) -> RegistrationCredential:
    """
    Parse a JSON form of a registration credential, as either a stringified JSON object or a
    plain dict, into an instance of RegistrationCredential
    """
    if isinstance(json_val, dict):
        json_val = json.dumps(json_val)

    try:
        registration_credential = RegistrationCredential()
    except Exception as exc:
        raise InvalidRegistrationResponse(
            "Unable to parse a registration credential from JSON data"
        ) from exc

    return registration_credential
