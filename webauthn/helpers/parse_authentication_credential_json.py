import json
from typing import Callable, Union

from .exceptions import InvalidAuthenticationResponse
from .structs import AuthenticationCredential


def parse_authentication_credential_json(json_val: Union[str, dict]) -> AuthenticationCredential:
    """
    Parse a JSON form of an authentication credential, as either a stringified JSON object or a
    plain dict, into an instance of AuthenticationCredential
    """
    if isinstance(json_val, dict):
        json_val = json.dumps(json_val)

    try:
        # TODO: Write this
        authentication_credential = AuthenticationCredential()
    except Exception as exc:
        raise InvalidAuthenticationResponse(
            "Unable to parse an authentication credential from JSON data"
        ) from exc

    return authentication_credential
