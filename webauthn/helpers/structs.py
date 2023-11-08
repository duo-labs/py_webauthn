from enum import Enum
from typing import Callable, List, Literal, Optional, Any, Dict


try:
    from pydantic import (  # type: ignore[attr-defined]
        BaseModel,
        field_validator,
        ConfigDict,
        FieldValidationInfo,
        model_serializer,
    )

    PYDANTIC_V2 = True
except ImportError:
    from pydantic import BaseModel, validator
    from pydantic.fields import ModelField  # type: ignore[attr-defined]

    PYDANTIC_V2 = False

from .base64url_to_bytes import base64url_to_bytes
from .bytes_to_base64url import bytes_to_base64url
from .cose import COSEAlgorithmIdentifier
from .json_loads_base64url_to_bytes import json_loads_base64url_to_bytes
from .snake_case_to_camel_case import snake_case_to_camel_case


def _to_bytes(v: Any) -> Any:
    if isinstance(v, bytes):
        """
        Return raw bytes from subclasses as well

        `strict_bytes_validator()` performs a similar check to this, but it passes through the
        subclass as-is and Pydantic then rejects it. Passing the subclass into `bytes()` lets us
        return `bytes` and make Pydantic happy.
        """
        return bytes(v)
    elif isinstance(v, memoryview):
        return v.tobytes()
    else:
        # Allow Pydantic to validate the field as usual to support the full range of bytes-like
        # values
        return v


class WebAuthnBaseModel(BaseModel):
    """
    A subclass of Pydantic's BaseModel that includes convenient defaults
    when working with WebAuthn data structures

    `modelInstance.json()` (to JSON):
    - Encodes bytes to Base64URL
    - Converts snake_case properties to camelCase

    `Model.parse_raw()` (from JSON):
    - Decodes Base64URL to bytes
    - Converts camelCase properties to snake_case
    """

    if PYDANTIC_V2:
        model_config = ConfigDict(  # type: ignore[typeddict-unknown-key]
            alias_generator=snake_case_to_camel_case,
            populate_by_name=True,
            ser_json_bytes="base64",
        )

        @field_validator("*", mode="before")
        def _pydantic_v2_validate_bytes_fields(
            cls, v: Any, info: FieldValidationInfo  # type: ignore[valid-type]
        ) -> Any:
            """
            `FieldValidationInfo` above is being deprecated for `ValidationInfo`, see the following:

            - https://github.com/pydantic/pydantic-core/issues/994
            - https://github.com/pydantic/pydantic/issues/7667

            There are now docs for the new way to access `field_name` that's only available in
            Pydantic v2.4+...

            https://docs.pydantic.dev/latest/concepts/types/#access-to-field-name

            This use of `FieldValidationInfo` will continue to work for now, but when it gets
            removed from Pydantic the `info.field_name` below will need to get updated to
            `info.data.field_name` after changing the type of `info` above to `ValidationInfo`
            """
            field = cls.model_fields[info.field_name]  # type: ignore[attr-defined]

            # UserHandle is defined as Optional[bytes] which is represented as:
            # field.annotation = typing.Optional[bytes]. So we handle that explicitly here.
            if field.annotation != bytes and info.field_name != 'user_handle':  # type: ignore[attr-defined]
                return v

            # base64 encoding is the standard used when serializing bytes for JSON
            # requests. For direct python the field value is assumed to already be bytes.
            if isinstance(v, str) and info.mode == "json":  # type: ignore[attr-defined]
                return base64url_to_bytes(v)

            return _to_bytes(v)

        @model_serializer(mode="wrap", when_used="json")
        def _pydantic_v2_serialize_bytes_fields(
            self, serializer: Callable[..., Dict[str, Any]]
        ) -> Dict[str, Any]:
            """
            Remove trailing "=" from bytes fields serialized as base64 encoded strings.
            """

            serialized = serializer(self)

            for name, field_info in self.model_fields.items():  # type: ignore[attr-defined]
                value = serialized.get(name)
                if field_info.annotation is bytes and isinstance(value, str):
                    serialized[name] = value.rstrip("=")

            return serialized

    else:

        class Config:
            json_encoders = {bytes: bytes_to_base64url}
            json_loads = json_loads_base64url_to_bytes
            alias_generator = snake_case_to_camel_case
            allow_population_by_field_name = True

        @validator("*", pre=True, allow_reuse=True)  # type: ignore[type-var]
        def _pydantic_v1_validate_bytes_fields(cls, v: Any, field: ModelField) -> Any:
            """
            Allow for Pydantic models to define fields as `bytes`, but allow consuming projects to
            specify bytes-adjacent values (bytes subclasses, memoryviews, etc...) that otherwise
            function like `bytes`. Keeps the library Pythonic.
            """
            if field.type_ != bytes:
                return v

            return _to_bytes(v)


################
#
# Fundamental data structures
#
################


class AuthenticatorTransport(str, Enum):
    """How an authenticator communicates to the client/browser.

    Members:
        `USB`: USB wired connection
        `NFC`: Near Field Communication
        `BLE`: Bluetooth Low Energy
        `INTERNAL`: Direct connection (read: a platform authenticator)
        `CABLE`: Cloud Assisted Bluetooth Low Energy
        `HYBRID`: A combination of (often separate) data-transport and proximity mechanisms

    https://www.w3.org/TR/webauthn-2/#enum-transport
    """

    USB = "usb"
    NFC = "nfc"
    BLE = "ble"
    INTERNAL = "internal"
    CABLE = "cable"
    HYBRID = "hybrid"


class AuthenticatorAttachment(str, Enum):
    """How an authenticator is connected to the client/browser.

    Members:
        `PLATFORM`: A non-removable authenticator, like TouchID or Windows Hello
        `CROSS_PLATFORM`: A "roaming" authenticator, like a YubiKey

    https://www.w3.org/TR/webauthn-2/#enumdef-authenticatorattachment
    """

    PLATFORM = "platform"
    CROSS_PLATFORM = "cross-platform"


class ResidentKeyRequirement(str, Enum):
    """The Relying Party's preference for the authenticator to create a dedicated "client-side" credential for it. Requiring an authenticator to store a dedicated credential should not be done lightly due to the limited storage capacity of some types of authenticators.

    Members:
        `DISCOURAGED`: The authenticator should not create a dedicated credential
        `PREFERRED`: The authenticator can create and store a dedicated credential, but if it doesn't that's alright too
        `REQUIRED`: The authenticator MUST create a dedicated credential. If it cannot, the RP is prepared for an error to occur.

    https://www.w3.org/TR/webauthn-2/#enum-residentKeyRequirement
    """

    DISCOURAGED = "discouraged"
    PREFERRED = "preferred"
    REQUIRED = "required"


class UserVerificationRequirement(str, Enum):
    """The degree to which the Relying Party wishes to verify a user's identity.

    Members:
        `REQUIRED`: User verification must occur
        `PREFERRED`: User verification would be great, but if not that's okay too
        `DISCOURAGED`: User verification should not occur, but it's okay if it does

    https://www.w3.org/TR/webauthn-2/#enumdef-userverificationrequirement
    """

    REQUIRED = "required"
    PREFERRED = "preferred"
    DISCOURAGED = "discouraged"


class AttestationConveyancePreference(str, Enum):
    """The Relying Party's interest in receiving an attestation statement.

    Members:
        `NONE`: The Relying Party isn't interested in receiving an attestation statement
        `INDIRECT`: The Relying Party is interested in an attestation statement, but the client is free to generate it as it sees fit
        `DIRECT`: The Relying Party is interested in an attestation statement generated directly by the authenticator
        `ENTERPRISE`: The Relying Party is interested in a statement with identifying information. Typically used within organizations

    https://www.w3.org/TR/webauthn-2/#enum-attestation-convey
    """

    NONE = "none"
    INDIRECT = "indirect"
    DIRECT = "direct"
    ENTERPRISE = "enterprise"


class PublicKeyCredentialType(str, Enum):
    """The type of credential that should be returned by an authenticator. There's but a single member because this is a specific subclass of a higher-level `CredentialType` that can be of other types.

    Members:
        `PUBLIC_KEY`: The literal string `"public-key"`

    https://www.w3.org/TR/webauthn-2/#enumdef-publickeycredentialtype
    """

    PUBLIC_KEY = "public-key"


class AttestationFormat(str, Enum):
    """The "syntax" of an attestation statement. Formats should be registered with the IANA and include documented signature verification steps.

    Members:
        `PACKED`
        `TPM`
        `ANDROID_KEY`
        `ANDROID_SAFETYNET`
        `FIDO_U2F`
        `APPLE`
        `NONE`

    https://www.iana.org/assignments/webauthn/webauthn.xhtml
    """

    PACKED = "packed"
    TPM = "tpm"
    ANDROID_KEY = "android-key"
    ANDROID_SAFETYNET = "android-safetynet"
    FIDO_U2F = "fido-u2f"
    APPLE = "apple"
    NONE = "none"


class ClientDataType(str, Enum):
    """Specific values included in authenticator registration and authentication responses to help avoid certain types of "signature confusion attacks".

    Members:
        `WEBAUTHN_CREATE`: The string "webauthn.create". Synonymous with `navigator.credentials.create()` in the browser
        `WEBAUTHN_GET`: The string "webauthn.get". Synonymous with `navigator.credentials.get()` in the browser

    https://www.w3.org/TR/webauthn-2/#dom-collectedclientdata-type
    """

    WEBAUTHN_CREATE = "webauthn.create"
    WEBAUTHN_GET = "webauthn.get"


class TokenBindingStatus(str, Enum):
    """
    https://www.w3.org/TR/webauthn-2/#dom-tokenbinding-status
    """

    PRESENT = "present"
    SUPPORTED = "supported"


class TokenBinding(WebAuthnBaseModel):
    """
    https://www.w3.org/TR/webauthn-2/#dictdef-tokenbinding
    """

    status: TokenBindingStatus
    id: Optional[str] = None


class PublicKeyCredentialRpEntity(WebAuthnBaseModel):
    """Information about the Relying Party.

    Attributes:
        `name`: A user-readable name for the Relying Party
        (optional) `id`: A unique, constant value assigned to the Relying Party. Authenticators use this value to associate a credential with a particular Relying Party user

    https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialrpentity
    """

    name: str
    id: Optional[str] = None


class PublicKeyCredentialUserEntity(WebAuthnBaseModel):
    """Information about a user of a Relying Party.

    Attributes:
        `id`: An "opaque byte sequence" that uniquely identifies a user. Typically something like a UUID, but never user-identifying like an email address. Cannot exceed 64 bytes.
        `name`: A value which a user can see to determine which account this credential is associated with. A username or email address is fine here.
        `display_name`: A user-friendly representation of a user, like a full name.

    https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialuserentity
    """

    id: bytes
    name: str
    display_name: str


class PublicKeyCredentialParameters(WebAuthnBaseModel):
    """Information about a cryptographic algorithm that may be used when creating a credential.

    Attributes:
        `type`: The literal string `"public-key"`
        `alg`: A numeric indicator of a particular algorithm

    https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialparameters
    """

    type: Literal["public-key"]
    alg: COSEAlgorithmIdentifier


class PublicKeyCredentialDescriptor(WebAuthnBaseModel):
    """Information about a generated credential.

    Attributes:
        `type`: The literal string `"public-key"`
        `id`: The sequence of bytes representing the credential's ID
        (optional) `transports`: The types of connections to the client/browser the authenticator supports

    https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialdescriptor
    """

    id: bytes
    type: Literal[
        PublicKeyCredentialType.PUBLIC_KEY
    ] = PublicKeyCredentialType.PUBLIC_KEY
    transports: Optional[List[AuthenticatorTransport]] = None


class AuthenticatorSelectionCriteria(WebAuthnBaseModel):
    """A Relying Party's requirements for the types of authenticators that may interact with the client/browser.

    Attributes:
        (optional) `authenticator_attachment`: How the authenticator can be connected to the client/browser
        (optional) `resident_key`: Whether the authenticator should be able to store a credential on itself
        (optional) `require_resident_key`: DEPRECATED, set a value for `resident_key` instead
        (optional) `user_verification`: How the authenticator should be capable of determining user identity

    https://www.w3.org/TR/webauthn-2/#dictdef-authenticatorselectioncriteria
    """

    authenticator_attachment: Optional[AuthenticatorAttachment] = None
    resident_key: Optional[ResidentKeyRequirement] = None
    require_resident_key: Optional[bool] = False
    user_verification: Optional[
        UserVerificationRequirement
    ] = UserVerificationRequirement.PREFERRED


class CollectedClientData(WebAuthnBaseModel):
    """Decoded ClientDataJSON

    Attributes:
        `type`: Either `"webauthn.create"` or `"webauthn.get"`, for registration and authentication ceremonies respectively
        `challenge`: The challenge passed to the authenticator within the options
        `origin`: The base domain with protocol on which the registration or authentication ceremony took place (e.g. "https://foo.bar")
        (optional) `cross_origin`: Whether or not the the registration or authentication ceremony took place on a different origin (think within an <iframe>)
        (optional) `token_binding`: Information on the state of the Token Binding protocol

    https://www.w3.org/TR/webauthn-2/#dictdef-collectedclientdata
    """

    type: ClientDataType
    challenge: bytes
    origin: str
    cross_origin: Optional[bool] = None
    token_binding: Optional[TokenBinding] = None


################
#
# Registration
#
################


class PublicKeyCredentialCreationOptions(WebAuthnBaseModel):
    """Registration Options.

    Attributes:
        `rp`: Information about the Relying Party
        `user`: Information about the user
        `challenge`: A unique byte sequence to be returned by the authenticator. Helps prevent replay attacks
        `pub_key_cred_params`: Cryptographic algorithms supported by the Relying Party when verifying signatures
        (optional) `timeout`: How long the client/browser should give the user to interact with an authenticator
        (optional) `exclude_credentials`: A list of credentials associated with the user to prevent them from re-enrolling one of them
        (optional) `authenticator_selection`: Additional qualities about the authenticators the user can use to complete registration
        (optional) `attestation`: The Relying Party's desire for a declaration of an authenticator's provenance via attestation statement

    https://www.w3.org/TR/webauthn-2/#dictdef-publickeycredentialcreationoptions
    """

    rp: PublicKeyCredentialRpEntity
    user: PublicKeyCredentialUserEntity
    challenge: bytes
    pub_key_cred_params: List[PublicKeyCredentialParameters]
    timeout: Optional[int] = None
    exclude_credentials: Optional[List[PublicKeyCredentialDescriptor]] = None
    authenticator_selection: Optional[AuthenticatorSelectionCriteria] = None
    attestation: AttestationConveyancePreference = AttestationConveyancePreference.NONE


class AuthenticatorAttestationResponse(WebAuthnBaseModel):
    """The `response` property on a registration credential.

    Attributes:
        `client_data_json`: Information the authenticator collects about the client/browser it communicates with
        `attestation_object`: Encoded information about an attestation
        (optional) `transports`: The authenticator's supported methods of communication with a client/browser

    https://www.w3.org/TR/webauthn-2/#authenticatorattestationresponse
    """

    client_data_json: bytes
    attestation_object: bytes
    # Optional in L2, but becomes required in L3. Play it safe until L3 becomes Recommendation
    transports: Optional[List[AuthenticatorTransport]] = None


class RegistrationCredential(WebAuthnBaseModel):
    """A registration-specific subclass of PublicKeyCredential returned from `navigator.credentials.create()`

    Attributes:
        `id`: The Base64URL-encoded representation of raw_id
        `raw_id`: A byte sequence representing the credential's unique identifier
        `response`: The authenticator's attesation data
        `type`: The literal string `"public-key"`

    https://www.w3.org/TR/webauthn-2/#publickeycredential
    """

    id: str
    raw_id: bytes
    response: AuthenticatorAttestationResponse
    authenticator_attachment: Optional[AuthenticatorAttachment] = None
    type: Literal[
        PublicKeyCredentialType.PUBLIC_KEY
    ] = PublicKeyCredentialType.PUBLIC_KEY


class AttestationStatement(WebAuthnBaseModel):
    """A collection of all possible fields that may exist in an attestation statement. Combinations of these fields are specific to a particular attestation format.

    https://www.w3.org/TR/webauthn-2/#sctn-defined-attestation-formats

    TODO: Decide if this is acceptable, or if we want to split this up into multiple
    format-specific classes that define only the fields that are present for a given
    attestation format.
    """

    sig: Optional[bytes] = None
    x5c: Optional[List[bytes]] = None
    response: Optional[bytes] = None
    alg: Optional[COSEAlgorithmIdentifier] = None
    ver: Optional[str] = None
    cert_info: Optional[bytes] = None
    pub_area: Optional[bytes] = None


class AuthenticatorDataFlags(WebAuthnBaseModel):
    """Flags the authenticator will set about information contained within the `attestationObject.authData` property.

    Attributes:
        `up`: [U]ser was [P]resent
        `uv`: [U]ser was [V]erified
        `be`: [B]ackup [E]ligible
        `bs`: [B]ackup [S]tate
        `at`: [AT]tested credential is included
        `ed`: [E]xtension [D]ata is included

    https://www.w3.org/TR/webauthn-2/#flags
    """

    up: bool
    uv: bool
    be: bool
    bs: bool
    at: bool
    ed: bool


class AttestedCredentialData(WebAuthnBaseModel):
    """Information about a credential.

    Attributes:
        `aaguid`: A 128-bit identifier indicating the type and vendor of the authenticator
        `credential_id`: The ID of the private/public key pair generated by the authenticator
        `credential_public_key`: The public key generated by the authenticator

    https://www.w3.org/TR/webauthn-2/#attested-credential-data
    """

    aaguid: bytes
    credential_id: bytes
    credential_public_key: bytes


class AuthenticatorData(WebAuthnBaseModel):
    """Context the authenticator provides about itself and the environment in which the registration or authentication ceremony took place.

    Attributes:
        `rp_id_hash`: A SHA-256 hash of the website origin on which the registration or authentication ceremony took place
        `flags`: Properties about the user and registration, where applicable
        `sign_count`: The number of times the credential was used
        (optional) `attested_credential_data`: Information about the credential created during a registration ceremony
        (optional) `extensions`: CBOR-encoded extension data corresponding to extensions specified in the registration or authentication ceremony options

    https://www.w3.org/TR/webauthn-2/#sctn-attestation
    https://www.w3.org/TR/webauthn-2/#sctn-attested-credential-data
    """

    rp_id_hash: bytes
    flags: AuthenticatorDataFlags
    sign_count: int
    attested_credential_data: Optional[AttestedCredentialData] = None
    extensions: Optional[bytes] = None


class AttestationObject(WebAuthnBaseModel):
    """Information about an attestation, including a statement and authenticator data.

    Attributes:
        `fmt`: The attestation statement's format
        `att_stmt`: An attestation statement to be verified according to the format
        `auth_data`: Contextual information provided by authenticator

    https://www.w3.org/TR/webauthn-2/#sctn-attestation
    """

    fmt: AttestationFormat
    auth_data: AuthenticatorData
    att_stmt: AttestationStatement = AttestationStatement()


################
#
# Authentication
#
################


class PublicKeyCredentialRequestOptions(WebAuthnBaseModel):
    """Authentication Options.

    Attributes:
        `challenge`: A unique byte sequence to be returned by the authenticator. Helps prevent replay attacks
        (optional) `timeout`: How long the client/browser should give the user to interact with an authenticator
        (optional) `rp_id`: The unique, constant identifier assigned to the Relying Party
        (optional) `allow_credentials`: A list of credentials associated with the user that they can use to complete the authentication
        (optional) `user_verification`: How the authenticator should be capable of determining user identity

    https://www.w3.org/TR/webauthn-2/#dictionary-assertion-options
    """

    challenge: bytes
    timeout: Optional[int] = None
    rp_id: Optional[str] = None
    allow_credentials: Optional[List[PublicKeyCredentialDescriptor]] = []
    user_verification: Optional[
        UserVerificationRequirement
    ] = UserVerificationRequirement.PREFERRED


class AuthenticatorAssertionResponse(WebAuthnBaseModel):
    """The `response` property on an authentication credential.

    Attributes:
        `client_data_json`: Information the authenticator collects about the client/browser it communicates with
        `authenticator_data`: Contextual information provided by authenticator
        `signature`: A byte sequence signed by the authenticator's private key, to be verified with a user's public key
        (optional) `user_handle`: The user ID specified for the user during attestation

    https://www.w3.org/TR/webauthn-2/#authenticatorassertionresponse
    """

    client_data_json: bytes
    authenticator_data: bytes
    signature: bytes
    user_handle: Optional[bytes] = None


class AuthenticationCredential(WebAuthnBaseModel):
    """An authentication-specific subclass of PublicKeyCredential. Returned from `navigator.credentials.get()`

    Attributes:
        `id`: The Base64URL-encoded representation of raw_id
        `raw_id`: A byte sequence representing the credential's unique identifier
        `response`: The authenticator's assertion data
        `type`: The literal string `"public-key"`

    https://www.w3.org/TR/webauthn-2/#publickeycredential
    """

    id: str
    raw_id: bytes
    response: AuthenticatorAssertionResponse
    authenticator_attachment: Optional[AuthenticatorAttachment] = None
    type: Literal[
        PublicKeyCredentialType.PUBLIC_KEY
    ] = PublicKeyCredentialType.PUBLIC_KEY


################
#
# Credential Backup State
#
################


class CredentialDeviceType(str, Enum):
    """A determination of the number of devices a credential can be used from

    Members:
        `SINGLE_DEVICE`: A credential that is bound to a single device
        `MULTI_DEVICE`: A credential that can be used from multiple devices (e.g. passkeys)

    https://w3c.github.io/webauthn/#sctn-credential-backup (L3 Draft)
    """

    SINGLE_DEVICE = "single_device"
    MULTI_DEVICE = "multi_device"
