from typing import Union

from .structs import (
    PYDANTIC_V2,
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
    if PYDANTIC_V2:
        json_options = options.model_dump_json(  # type: ignore[union-attr]
            by_alias=True,
            exclude_unset=False,
            exclude_none=True,
        )

    else:
        json_options = options.json(
            by_alias=True,
            exclude_unset=False,
            exclude_none=True,
        )

    return json_options
