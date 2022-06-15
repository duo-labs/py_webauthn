from typing import Union

from .structs import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
)


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
