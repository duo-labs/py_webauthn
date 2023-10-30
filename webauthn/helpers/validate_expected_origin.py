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
from urllib.parse import urlparse

WILDCARD_DELIMITER = "*."


def match_wildcard_origin(origin1: str, origin2: str) -> bool:
    """
    Perform wildcard match of two origins.

    This covers the case where the expected origin has a "*." prefix
    on the domain, allowing subdomains to match.

    e.g. https://*.example.com will match https://foo.example.com, but
    not https://example.com.

    If the port number is supplied for either origin then they must
    match.

    See tests for more examples.

    Args:
        `origin1`: The origin that contains the wildcard ("*").
        `origin2`: The (fully-qualified) origin to match with.

    """
    if WILDCARD_DELIMITER not in origin1:
        return False

    parts1 = urlparse(origin1)
    if not parts1.scheme:
        raise ValueError("Expected origin must include a scheme")

    parts2 = urlparse(origin2)

    # schemes must match
    if parts1.scheme != parts2.scheme:
        return False

    # if either origin has a port number, they must match
    if (parts1.port or parts2.port) and parts1.port != parts2.port:
        return False

    # split off wildcard part of origin1 and check origin2 ends with it
    suffix = parts1.netloc.rsplit(WILDCARD_DELIMITER, 1)[1]
    # NB "*.example.com" should not match "example.com" exactly
    return parts2.netloc.endswith(suffix) and parts2.netloc != suffix


def match_origin(expected_origin: str, origin: str) -> bool:
    """
    Match a single origin against an expected origin.

    This function handles the subdomain wildcard, so that an expected
    origin of "https://*.example.com" will match "https://foo.example.com".

    Args:
        `expected_origin`: The origin that is expected - which may include
            the "*" wildcard to match any subdomain. Must include scheme.
        `origin`: The (fully-qualified) origin to validate, as returned by
            the browser in the ClientDataJSON.

    """
    # straight match
    if origin == expected_origin:
        return True

    # check for a wildcard match - involves parsing url
    return match_wildcard_origin(expected_origin, origin)


def validate_expected_origin(
        expected_origin: Union[str, List[str]],
        origin: str
    ) -> bool:
    """
    Validate that the origin matches the expected origin.

    See https://www.w3.org/TR/webauthn-3/#sctn-validating-origin

    Args:
        `expected_origin`: The origin that is expected - may be a string
            or list of strings, any of which may include the "*"
            wildcard to match any subdomain.
        `origin`: The (fully-qualified) origin to validate.

    """
    # convert single string to list so we can treat all the same
    if isinstance(expected_origin, str):
        return match_origin(expected_origin, origin)

    return any(match_origin(expected, origin) for expected in expected_origin)
