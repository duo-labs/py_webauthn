"""
Validation of the origin passed in via ClientDataJSON.

See https://www.w3.org/TR/webauthn-3/#sctn-validating-origin

---

From the specification there are two main rules:

    The Relying Party MUST validate the origin member of the client data.

    The Relying Party MUST NOT accept unexpected values of origin [...]

Regarding the validation itself, the spec is more open:

    Validation MAY be performed by exact string matching _or any other
    method_ as needed by the Relying Party.

"Any other method" is an open door - this method implements a simple
wildcard matching scheme. If there is no exact match and the expected
origin contains a "*" (wildcard char) then it splits the value into a
prefix / suffix and checks that the origin starts with the prefix and
ends with the suffix.

This method does allow a very broad match - e.g. "*" on its own splits
into ('', '') and will match any origin.

"""
from typing import List, Union


def match_origins(expected_origin: str, origin: str) -> bool:
    """Compare two origins for a match (supports wildcards)."""
    if expected_origin == origin:
        return True

    # neither exact match nor wildcard match
    if "*" not in expected_origin:
        return False

    try:
        startswith, endswith = expected_origin.split("*")
    except ValueError:
        # this will raise InvalideAuthenticationResponse or
        # InvalidRegistrationResponse depending on where it is called
        return False

    # NB "*" will match anything, effectively disabling origin validation.
    return origin.startswith(startswith) and origin.endswith(endswith)


def validate_expected_origin(
        expected_origin: Union[str, List[str]],
        origin: str
    ) -> bool:
    """
    Validate that the origin matches the expected origin.

    This is the main entry point for validating the origin - it will
    validate a client data origin against the expected origin which may
    be a single string or a list of strings, any of which may include
    the "*" wildcard to match any subdomain.

    See https://www.w3.org/TR/webauthn-3/#sctn-validating-origin

    Args:
        `expected_origin`: The origin that is expected - may be a string
            or list of strings, any of which may include the "*"
            wildcard to match any subdomain.
        `origin`: The (fully-qualified) origin to validate.

    """
    if not expected_origin:
        return False

    if isinstance(expected_origin, str):
        return match_origins(expected_origin, origin)

    if isinstance(expected_origin, list):
        return any(match_origins(expected, origin) for expected in expected_origin)

    return False
