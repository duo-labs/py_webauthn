# Authenticator data flags.
# https://www.w3.org/TR/webauthn/#authenticator-data
USER_PRESENT = 1 << 0
USER_VERIFIED = 1 << 2
ATTESTATION_DATA_INCLUDED = 1 << 6
EXTENSION_DATA_INCLUDED = 1 << 7
