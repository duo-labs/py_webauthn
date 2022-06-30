from enum import Enum
from pydantic import BaseModel

from .structs import AuthenticatorDataFlags
from .exceptions import InvalidBackupFlags


class CredentialDeviceType(str, Enum):
    """A determination of the number of devices a credential can be used from

    Members:
        `SINGLE_DEVICE`: A credential that is bound to a single device
        `MULTI_DEVICE`: A credential that can be used from multiple devices (e.g. passkeys)

    https://w3c.github.io/webauthn/#sctn-credential-backup (L3 Draft)
    """

    SINGLE_DEVICE = "single_device"
    MULTI_DEVICE = "multi_device"


class ParsedBackupFlags(BaseModel):
    credential_device_type: CredentialDeviceType
    credential_backed_up: bool


def parse_backup_flags(flags: AuthenticatorDataFlags) -> ParsedBackupFlags:
    """Parse backup eligibility and backup state flags into more useful representations

    Raises:
        `helpers.exceptions.InvalidBackupFlags` if an invalid backup state is detected
    """
    credential_device_type = CredentialDeviceType.SINGLE_DEVICE

    # A credential that can be backed up can typically be used on multiple devices
    if flags.be:
        credential_device_type = CredentialDeviceType.MULTI_DEVICE

    if credential_device_type == CredentialDeviceType.SINGLE_DEVICE and flags.bs:
        raise InvalidBackupFlags(
            "Single-device credential indicated that it was backed up, which should be impossible."
        )

    return ParsedBackupFlags(
        credential_device_type=credential_device_type,
        credential_backed_up=flags.bs,
    )
