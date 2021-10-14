from webauthn.authentication import generate_authentication_options
from webauthn.helpers import options_to_json
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.registration import generate_registration_options

################
#
# Examples of using webauthn to generate registration options
#
# See these in action by executing this file from the root of this project:
#
# `python -m examples.options`
#
################

# Simple
simple_registration_options = generate_registration_options(
    rp_id="example.com",
    rp_name="Example Co",
    user_id="12345",
    user_name="bob",
)

print("\n[Registration Options - Simple]")
print(options_to_json(simple_registration_options))

# Complex
complex_registration_options = generate_registration_options(
    rp_id="example.com",
    rp_name="Example Co",
    user_id="ABAV6QWPBEY9WOTOA1A4",
    user_name="lee",
    user_display_name="Lee",
    attestation=AttestationConveyancePreference.DIRECT,
    authenticator_selection=AuthenticatorSelectionCriteria(
        authenticator_attachment=AuthenticatorAttachment.PLATFORM,
        resident_key=ResidentKeyRequirement.REQUIRED,
    ),
    challenge=b"1234567890",
    exclude_credentials=[
        PublicKeyCredentialDescriptor(id=b"1234567890"),
    ],
    supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_512],
    timeout=12000,
)

print("\n[Registration Options - Complex]")
print(options_to_json(complex_registration_options))

################
#
# Examples of using webauthn to generate authentication options
#
################

simple_authentication_options = generate_authentication_options(rp_id="example.com")

print("\n[Authentication Options - Simple]")
print(options_to_json(simple_authentication_options))

complex_authentication_options = generate_authentication_options(
    rp_id="example.com",
    challenge=b"1234567890",
    timeout=12000,
    allow_credentials=[PublicKeyCredentialDescriptor(id=b"1234567890")],
    user_verification=UserVerificationRequirement.REQUIRED,
)

print("\n[Authentication Options - Complex]")
print(options_to_json(complex_authentication_options))
