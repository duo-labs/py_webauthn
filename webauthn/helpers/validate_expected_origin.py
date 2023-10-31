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


def is_exact_match(expected_origin: str, origin: str) -> bool:
    """
    Return True for a case-insensitive match of two origins.

    Args:
        `expected_origin`: The origin that contains the wildcard ("*").
        `origin`: The (fully-qualified) origin to match against.

    """
    return expected_origin.lower() == origin.lower()


def is_wildcard_match(expected_origin: str, origin: str) -> bool:
    """
    Perform subdomain-agnostic match of two http(s) origins.

    This covers the case where the expected origin has a "*." prefix
    on the domain, allowing subdomains to match.

    e.g. https://*.example.com will match https://foo.example.com, but
    not https://example.com.

    If the port number is supplied for either origin then they must
    match.

    See tests for more examples.

    Args:
        `expected_origin`: The origin that contains the wildcard ("*").
        `origin`: The (fully-qualified) origin to match against.

    """
    # if this isn't a wildcard origin, do an exact match
    if "*" not in expected_origin:
        return is_exact_match(expected_origin, origin)

    # wildcards only (currently) supported with http(s) schemes
    if not expected_origin.startswith("http"):
        return False

    # split the origins so we can compare scheme and port
    parts1 = urlparse(expected_origin)
    parts2 = urlparse(origin)

    # schemes must match
    if parts1.scheme != parts2.scheme:
        return False

    # if either origin has a port number, they must match
    if (parts1.port or parts2.port) and parts1.port != parts2.port:
        return False

    # split off wildcard part of origin1 and check origin2 ends with it
    suffix = parts1.netloc.rsplit("*", 1)[1]
    # NB "*.example.com" should not match "example.com" exactly
    return parts2.netloc.endswith(suffix) and parts2.netloc != suffix


def match_origins(expected_origin, origin) -> bool:
    """Compare two origins for a match (supports wildcards)."""
    return (
        is_exact_match(expected_origin, origin) or
        is_wildcard_match(expected_origin, origin)
    )


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
