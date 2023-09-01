from typing import Union

from .structs import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
)


def options_to_json(
    options: Union[
        PublicKeyCredentialCreationOptions,
        PublicKeyCredentialRequestOptions,
    ],
    indent: int|None=None,
) -> str:
    """
    Prepare options for transmission to the front end as JSON
    """
    if hasattr(options, 'model_dump_json'): # model_dump_json was introduced in v2..
        return options.model_dump_json(     # ..won't work in v1.
            by_alias=True,
            exclude_unset=False,
            exclude_none=True,
            indent=indent,
        )
    else:
        return options.json(  # noqa: D102
            by_alias=True,
            exclude_unset=False,
            exclude_none=False,
            indent=indent,
        )
