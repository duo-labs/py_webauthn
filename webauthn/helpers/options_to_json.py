from typing import Union

from .structs import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
)
from .snake_case_to_camel_case import snake_case_to_camel_case
from .bytes_to_base64url import bytes_to_base64url


def options_to_json(
    options: Union[
        PublicKeyCredentialCreationOptions,
        PublicKeyCredentialRequestOptions,
    ]
) -> str:
    """
    Prepare options for transmission to the front end as JSON
    """
    return options.json(
        by_alias=True,
        exclude_unset=False,
        exclude_none=True,
    )
