import json
from typing import Union

from attr import has, fields
from cattr.preconf.json import make_converter
from cattr.gen import make_dict_unstructure_fn, make_dict_structure_fn, override

from .structs import (
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialRequestOptions,
)
from .snake_case_to_camel_case import snake_case_to_camel_case
from .bytes_to_base64url import bytes_to_base64url


# Create a converter to convert our attr classes into JSON strings
converter = make_converter()
# Convert snake_case property names to camelCase
def _to_camel_case_unstructure(cls):
    return make_dict_unstructure_fn(
        cls,
        converter,
        **{
            attribute.name: override(
                # Avoid sending optional `None` defaults as `null` in JSON
                omit_if_default=attribute.default is None,
                rename=snake_case_to_camel_case(attribute.name),
            )
            for attribute in fields(cls)
        }
    )


converter.register_unstructure_hook_factory(has, _to_camel_case_unstructure)
# Encode bytes values to base64url
converter.register_unstructure_hook(bytes, bytes_to_base64url)


def options_to_json(
    options: Union[
        PublicKeyCredentialCreationOptions,
        PublicKeyCredentialRequestOptions,
    ]
) -> str:
    """
    Prepare options for transmission to the front end as JSON
    """
    return json.dumps(converter.unstructure(options))
