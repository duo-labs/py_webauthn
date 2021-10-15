import json
from typing import Any, Union

from .base64url_to_bytes import base64url_to_bytes


def _object_hook_base64url_to_bytes(orig_dict: dict) -> dict:
    """
    A function for the `object_hook` argument in json.loads() that knows which fields in
    an incoming JSON string need to be converted from Base64URL to bytes.
    """
    # Registration and Authentication
    if "rawId" in orig_dict:
        orig_dict["rawId"] = base64url_to_bytes(orig_dict["rawId"])
    if "clientDataJSON" in orig_dict:
        orig_dict["clientDataJSON"] = base64url_to_bytes(orig_dict["clientDataJSON"])
    # Registration
    if "attestationObject" in orig_dict:
        orig_dict["attestationObject"] = base64url_to_bytes(
            orig_dict["attestationObject"]
        )
    # Authentication
    if "authenticatorData" in orig_dict:
        orig_dict["authenticatorData"] = base64url_to_bytes(
            orig_dict["authenticatorData"]
        )
    if "signature" in orig_dict:
        orig_dict["signature"] = base64url_to_bytes(orig_dict["signature"])
    if "userHandle" in orig_dict:
        orig_dict["userHandle"] = base64url_to_bytes(orig_dict["userHandle"])
    return orig_dict


def json_loads_base64url_to_bytes(input: Union[str, bytes]) -> Any:
    """
    Wrap `json.loads()` with a custom object_hook that knows which dict keys to convert
    from Base64URL to bytes when converting from JSON to Pydantic model
    """
    return json.loads(input, object_hook=_object_hook_base64url_to_bytes)
