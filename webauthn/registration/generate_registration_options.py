from typing import List, Optional

from webauthn.helpers import generate_challenge
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParameters,
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
)


def _generate_pub_key_cred_params(
    supported_algs: List[COSEAlgorithmIdentifier],
) -> List[PublicKeyCredentialParameters]:
    """
    Take an array of algorithm ID ints and return an array of PublicKeyCredentialParameters
    """
    return [
        PublicKeyCredentialParameters(type="public-key", alg=alg)
        for alg in supported_algs
    ]


default_supported_pub_key_algs = [
    COSEAlgorithmIdentifier.ECDSA_SHA_256,
    COSEAlgorithmIdentifier.EDDSA,
    COSEAlgorithmIdentifier.ECDSA_SHA_512,
    COSEAlgorithmIdentifier.RSASSA_PSS_SHA_256,
    COSEAlgorithmIdentifier.RSASSA_PSS_SHA_384,
    COSEAlgorithmIdentifier.RSASSA_PSS_SHA_512,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_384,
    COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_512,
]
default_supported_pub_key_params = _generate_pub_key_cred_params(
    default_supported_pub_key_algs,
)


def generate_registration_options(
    *,
    rp_id: str,
    rp_name: str,
    user_id: str,
    user_name: str,
    user_display_name: Optional[str] = None,
    challenge: Optional[bytes] = None,
    timeout: int = 60000,
    attestation: AttestationConveyancePreference = AttestationConveyancePreference.NONE,
    authenticator_selection: Optional[AuthenticatorSelectionCriteria] = None,
    exclude_credentials: Optional[List[PublicKeyCredentialDescriptor]] = None,
    supported_pub_key_algs: Optional[List[COSEAlgorithmIdentifier]] = None,
) -> PublicKeyCredentialCreationOptions:
    """Generate options for registering a credential via navigator.credentials.create()

    Args:
        `rp_id`: A unique, constant identifier for this Relying Party.
        `rp_name`: A user-friendly, readable name for the Relying Party.
        `user_id`: A unique identifier for the user. For privacy reasons it should NOT be something like an email address.
        `user_name`: A value that will help the user identify which account this credential is associated with. Can be an email address, etc...
        (optional) `user_display_name`: A user-friendly representation of their account. Can be a full name ,etc... Defaults to the value of `user_name`.
        (optional) `challenge`: A byte sequence for the authenticator to return back in its response. If no value is specified then a sequence of random bytes will be generated.
        (optional) `timeout`: How long in milliseconds the browser should give the user to choose an authenticator. This value is a *hint* and may be ignored by the browser.
        (optional) `attestation`: The level of attestation to be provided by the authenticator.
        (optional) `authenticator_selection`: Require certain characteristics about an authenticator, like attachment, support for resident keys, user verification, etc...
        (optional) `exclude_credentials`: A list of credentials the user has previously registered so that they cannot re-register them.
        (optional) `supported_pub_key_algs`: A list of public key algorithm IDs the RP chooses to restrict support to. Defaults to all supported algorithm IDs.

    Returns:
        Registration options ready for the browser. Consider using `helpers.options_to_json()` in this library to quickly convert the options to JSON.
    """

    ########
    # Set defaults for required values
    ########

    if not user_display_name:
        user_display_name = user_name

    pub_key_cred_params = default_supported_pub_key_params
    if supported_pub_key_algs:
        pub_key_cred_params = _generate_pub_key_cred_params(supported_pub_key_algs)

    if not challenge:
        challenge = generate_challenge()

    if not exclude_credentials:
        exclude_credentials = []

    ########
    # Generate the actual options
    ########

    options = PublicKeyCredentialCreationOptions(
        rp=PublicKeyCredentialRpEntity(
            name=rp_name,
            id=rp_id,
        ),
        user=PublicKeyCredentialUserEntity(
            id=user_id.encode("utf-8"),
            name=user_name,
            display_name=user_display_name,
        ),
        challenge=challenge,
        pub_key_cred_params=pub_key_cred_params,
        timeout=timeout,
        exclude_credentials=exclude_credentials,
        attestation=attestation,
    )

    ########
    # Set optional values if specified
    ########

    if authenticator_selection is not None:
        # "Relying Parties SHOULD set [requireResidentKey] to true if, and only if,
        # residentKey is set to "required""
        #
        # See https://www.w3.org/TR/webauthn-2/#dom-authenticatorselectioncriteria-requireresidentkey
        if authenticator_selection.resident_key == ResidentKeyRequirement.REQUIRED:
            authenticator_selection.require_resident_key = True
        options.authenticator_selection = authenticator_selection

    return options
