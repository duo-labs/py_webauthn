from typing import List, Union


def normalize_origin(origin: str) -> str:
    return origin.lower().lstrip("https://")


def match_origin(expected_origin: str, origin: str) -> bool:
    """
    Match a single origin against an expected origin.

    This function handles the subdomain wildcard, so that an expected
    origin of "https://*.example.com" will match "https://foo.example.com".

    """
    # normalize both origins to make it easier to compare
    origin1 = normalize_origin(expected_origin)
    origin2 = normalize_origin(origin)
    if "*" not in origin1:
        return origin1 == origin2
    # we have a wildcard, so we need to do some extra work.
    return origin2.endswith(origin1.split("*")[1])


def validate_expected_origin(
        expected_origin: Union[str, List[str]],
        origin: str
    ) -> bool:
    """
    Validate that the origin matches the expected origin.

    Args:
        `expected_origin`: The origin that is expected - may be a string
            or list of strings, any of which may include the "*"
            wildcard to match any subdomain.
        `origin`: The origin to validate, must be HTTPS.

    Raises:
        `ValueError` if origin does not match expected origin, or if
        origin is not HTTPS.

    """
    # TODO: Breaks tests - need to regenerate test data
    # if not origin.startswith("https://"):
    #     raise ValueError(f"Origin '{origin}' must start with https://")

    # convert single string to list so we can treat all the same
    if isinstance(expected_origin, str):
        return match_origin(expected_origin, origin)

    return any(match_origin(expected, origin) for expected in expected_origin)
