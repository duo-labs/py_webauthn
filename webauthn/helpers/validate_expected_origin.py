"""
Validation of the origin passed in via ClientDataJSON.

See https://www.w3.org/TR/webauthn-3/#sctn-validating-origin

---
The Relying Party MUST NOT accept unexpected values of origin, as doing
so could allow a malicious website to obtain valid credentials. Although
the scope of WebAuthn credentials prevents their use on domains outside
the RP ID they were registered for, the Relying Party's origin
validation serves as an additional layer of protection in case a faulty
authenticator fails to enforce credential scope. See also §13.4.8 Code
injection attacks for discussion of potentially malicious subdomains.

Validation MAY be performed by exact string matching or any other method
as needed by the Relying Party. For example:

- A web application served only at https://example.org SHOULD require
origin to exactly equal https://example.org.

This is the simplest case, where origin is expected to be the string
https:// followed by the RP ID.

- A web application served at a small number of domains might require
origin to exactly equal some element of a list of allowed origins, for
example the list ["https://example.org", "https://login.example.org"].

- A web application served at a large set of domains that changes often
might parse origin structurally and require that the URL scheme is https
and that the authority equals or is any subdomain of the RP ID - for
example, example.org or any subdomain of example.org).

NOTE: See §13.4.8 Code injection attacks for a discussion of the risks
of allowing any subdomain of the RP ID.

A web application with a companion native application might allow origin
to be an operating system dependent identifier for the native
application. For example, such a Relying Party might require that origin
exactly equals some element of the list ["https://example.org",
"example-os:appid:204ffa1a5af110ac483f131a1bef8a841a7a"].

"""
from typing import List, Union

from .exceptions import InvalidExpectedOrigin


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
        raise InvalidExpectedOrigin("Wildcard origin must contain exactly one '*'")

    # NB this allows very broad matches, e.g. "http*" will match any web url
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
    if isinstance(expected_origin, str):
        return match_origins(expected_origin, origin)

    return any(match_origins(expected, origin) for expected in expected_origin)
