from __future__ import print_function

import base64
import hashlib
import json
import os
import struct
import sys

import cbor2
import six

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import load_der_x509_certificate
from OpenSSL import crypto

import const


# Only supporting 'None', 'Basic', and 'Self Attestation' attestation types for now.
AT_BASIC = 'Basic'
AT_ECDAA = 'ECDAA'
AT_NONE = 'None'
AT_ATTESTATION_CA = 'AttCA'
AT_SELF_ATTESTATION = 'Self'

SUPPORTED_ATTESTATION_TYPES = (
    AT_BASIC,
    AT_NONE,
    AT_SELF_ATTESTATION
)

# Only supporting 'fido-u2f' and 'none' attestation formats for now.
SUPPORTED_ATTESTATION_FORMATS = (
    'fido-u2f',
    'none',
)

# Trust anchors (trusted attestation roots directory).
DEFAULT_TRUST_ANCHOR_DIR = 'trusted_attestation_roots'

# Client data type.
TYPE_CREATE = 'webauthn.create'
TYPE_GET = 'webauthn.get'

# Expected client extensions
EXPECTED_CLIENT_EXTENSIONS = {
    'appid': None,
    'loc': None
}

# Expected authenticator extensions
EXPECTED_AUTHENTICATOR_EXTENSIONS = {
}


class AuthenticationRejectedException(Exception):
    pass


class RegistrationRejectedException(Exception):
    pass


class WebAuthnMakeCredentialOptions(object):

    def __init__(self,
                 challenge,
                 rp_name,
                 rp_id,
                 user_id,
                 username,
                 display_name,
                 icon_url):
        self.challenge = challenge
        self.rp_name = rp_name
        self.rp_id = rp_id
        self.user_id = user_id
        self.username = username
        self.display_name = display_name
        self.icon_url = icon_url

    @property
    def registration_dict(self):
        registration_dict = {
            'challenge': self.challenge,
            'rp': {
                'name': self.rp_name,
                'id': self.rp_id
            },
            'user': {
                'id': self.user_id,
                'name': self.username,
                'displayName': self.display_name,
                'icon': self.icon_url
            },
            'pubKeyCredParams': [
                {
                    'alg': 'ES256',
                    'type': 'public-key',
                },
                {
                    'alg': -7,
                    'type': 'public-key',
                }
            ],
            'timeout': 60000,  # 1 minute.
            'excludeCredentials': [],
            # Relying Parties may use AttestationConveyancePreference to specify their
            # preference regarding attestation conveyance during credential generation.
            'attestation': 'direct',  # none, indirect, direct
            'extensions': {
                # Include location information in attestation.
                'webauthn.loc': True
            }
        }

        return registration_dict

    @property
    def json(self):
        return json.dumps(self.registration_dict)


class WebAuthnAssertionOptions(object):

    def __init__(self, webauthn_user, challenge):
        self.webauthn_user = webauthn_user
        self.challenge = challenge

    @property
    def assertion_dict(self):
        if not isinstance(self.webauthn_user, WebAuthnUser):
            raise AuthenticationRejectedException('Invalid user type.')
        if not self.webauthn_user.credential_id:
            raise AuthenticationRejectedException('Invalid credential ID.')
        if not self.challenge:
            raise AuthenticationRejectedException('Invalid challenge.')

        # TODO: Handle multiple acceptable credentials.
        acceptable_credential = {
            'type': 'public-key',
            'id': self.webauthn_user.credential_id,
            'transports': ['usb', 'nfc', 'ble']
        }

        assertion_dict = {
            'challenge': self.challenge,
            'timeout': 60000,  # 1 minute.
            'allowCredentials': [
                acceptable_credential,
            ],
            'rpId': self.webauthn_user.rp_id,
            # 'extensions': {}
        }

        return assertion_dict

    @property
    def json(self):
        return json.dumps(self.assertion_dict)


class WebAuthnUser(object):

    def __init__(self,
                 user_id,
                 username,
                 display_name,
                 icon_url,
                 credential_id,
                 public_key,
                 sign_count,
                 rp_id):
        self.user_id = user_id
        self.username = username
        self.display_name = display_name
        self.icon_url = icon_url
        self.credential_id = credential_id
        self.public_key = public_key
        self.sign_count = sign_count
        self.rp_id = rp_id

    def __str__(self):
        return '{} ({}, {}, {})'.format(
            self.user_id,
            self.username,
            self.display_name,
            self.sign_count)


class WebAuthnCredential(object):

    def __init__(self,
                 rp_id,
                 origin,
                 credential_id,
                 public_key,
                 sign_count):
        self.rp_id = rp_id
        self.origin = origin
        self.credential_id = credential_id
        self.public_key = public_key
        self.sign_count = sign_count

    def __str__(self):
        return '{} ({}, {}, {})'.format(
            self.credential_id,
            self.rp_id,
            self.origin,
            self.sign_count)


class WebAuthnRegistrationResponse(object):

    def __init__(self,
                 rp_id,
                 origin,
                 registration_response,
                 challenge,
                 trust_anchor_dir=DEFAULT_TRUST_ANCHOR_DIR,
                 trusted_attestation_cert_required=False,
                 self_attestation_permitted=False,
                 none_attestation_permitted=False,
                 uv_required=False):
        self.rp_id = rp_id
        self.origin = origin
        self.registration_response = registration_response
        self.challenge = challenge
        self.trust_anchor_dir = trust_anchor_dir
        self.trusted_attestation_cert_required = trusted_attestation_cert_required
        self.uv_required = uv_required

        # With self attestation, the credential public key is
        # also used as the attestation public key.
        self.self_attestation_permitted = self_attestation_permitted

        # `none` AttestationConveyancePreference
        # Replace potentially uniquely identifying information
        # (such as AAGUID and attestation certificates) in the
        # attested credential data and attestation statement,
        # respectively, with blinded versions of the same data.
        # **Note**: If True, authenticator attestation will not
        #           be performed.
        self.none_attestation_permitted = none_attestation_permitted

    def _verify_attestation_statement(self, fmt, att_stmt, auth_data, client_data_hash):
        '''Verification procedure: The procedure for verifying an attestation statement,
        which takes the following verification procedure inputs:

            * attStmt: The attestation statement structure
            * authenticatorData: The authenticator data claimed to have been used for
                                 the attestation
            * clientDataHash: The hash of the serialized client data

        The procedure returns either:

            * An error indicating that the attestation is invalid, or
            * The attestation type, and the trust path. This attestation trust path is
              either empty (in case of self attestation), an identifier of an ECDAA-Issuer
              public key (in the case of ECDAA), or a set of X.509 certificates.

        TODO:
        Verification of attestation objects requires that the Relying Party has a trusted
        method of determining acceptable trust anchors in step 15 above. Also, if
        certificates are being used, the Relying Party MUST have access to certificate
        status information for the intermediate CA certificates. The Relying Party MUST
        also be able to build the attestation certificate chain if the client did not
        provide this chain in the attestation information.
        '''
        if fmt == 'fido-u2f':
            # Step 1.
            #
            # Verify that attStmt is valid CBOR conforming to the syntax
            # defined above and perform CBOR decoding on it to extract the
            # contained fields.
            if 'x5c' not in att_stmt or 'sig' not in att_stmt:
                raise RegistrationRejectedException(
                    'Attestation statement must be a valid CBOR object.')

            # Step 2.
            #
            # Let attCert be the value of the first element of x5c. Let certificate
            # public key be the public key conveyed by attCert. If certificate public
            # key is not an Elliptic Curve (EC) public key over the P-256 curve,
            # terminate this algorithm and return an appropriate error.
            att_cert = att_stmt.get('x5c')[0]
            x509_att_cert = load_der_x509_certificate(att_cert, default_backend())
            certificate_public_key = x509_att_cert.public_key()
            if not isinstance(certificate_public_key.curve, SECP256R1):
                raise RegistrationRejectedException('Bad certificate public key.')

            # Step 3.
            #
            # Extract the claimed rpIdHash from authenticatorData, and the
            # claimed credentialId and credentialPublicKey from
            # authenticatorData.attestedCredentialData.
            attestation_data = auth_data[37:]
            aaguid = attestation_data[:16]
            credential_id_len = struct.unpack('!H', attestation_data[16:18])[0]
            cred_id = attestation_data[18:18 + credential_id_len]
            credential_pub_key = attestation_data[18 + credential_id_len:]

            # The credential public key encoded in COSE_Key format, as defined in Section 7
            # of [RFC8152], using the CTAP2 canonical CBOR encoding form. The COSE_Key-encoded
            # credential public key MUST contain the optional "alg" parameter and MUST NOT
            # contain any other optional parameters. The "alg" parameter MUST contain a
            # COSEAlgorithmIdentifier value. The encoded credential public key MUST also
            # contain any additional required parameters stipulated by the relevant key type
            # specification, i.e., required for the key type "kty" and algorithm "alg" (see
            # Section 8 of [RFC8152]).
            cpk = cbor2.loads(credential_pub_key)

            # Credential public key parameter names via the COSE_Key spec (for ES256).
            alg_key = 3
            x_key = -2
            y_key = -3

            if alg_key not in cpk:
                raise RegistrationRejectedException(
                    "Credential public key missing required algorithm parameter.")

            required_keys = {alg_key, x_key, y_key}
            cpk_keys = cpk.keys()

            if not set(cpk_keys).issuperset(required_keys):
                raise RegistrationRejectedException(
                    'Credential public key must match COSE_Key spec.')

            # A COSEAlgorithmIdentifier's value is a number identifying
            # a cryptographic algorithm. The algorithm identifiers SHOULD
            # be values registered in the IANA COSE Algorithms registry
            # [IANA-COSE-ALGS-REG], for instance, -7 for "ES256" and -257
            # for "RS256".
            # https://www.iana.org/assignments/cose/cose.xhtml#algorithms

            # For now we are only supporting ES256 as an algorithm.
            ES256 = -7
            if cpk[alg_key] != ES256:
                raise RegistrationRejectedException('Unsupported algorithm.')

            # Step 4.
            #
            # Convert the COSE_KEY formatted credentialPublicKey (see Section 7
            # of [RFC8152]) to CTAP1/U2F public Key format [FIDO-CTAP].

            # Let publicKeyU2F represent the result of the conversion operation
            # and set its first byte to 0x04. Note: This signifies uncompressed
            # ECC key format.
            public_key_u2f = ''  # 0x04 byte prepended in `_encode_public_key` function.

            # Extract the value corresponding to the "-2" key (representing x coordinate)
            # from credentialPublicKey, confirm its size to be of 32 bytes and concatenate
            # it with publicKeyU2F. If size differs or "-2" key is not found, terminate
            # this algorithm and return an appropriate error.
            x = cpk[x_key].encode('hex')
            if len(x) != 64:
                raise RegistrationRejectedException('Bad public key.')
            x_long = long(x, 16)

            # Extract the value corresponding to the "-3" key (representing y coordinate)
            # from credentialPublicKey, confirm its size to be of 32 bytes and concatenate
            # it with publicKeyU2F. If size differs or "-3" key is not found, terminate
            # this algorithm and return an appropriate error.
            y = cpk[y_key].encode('hex')
            if len(y) != 64:
                raise RegistrationRejectedException('Bad public key.')
            y_long = long(y, 16)

            user_ec = EllipticCurvePublicNumbers(
                x_long, y_long,
                SECP256R1()).public_key(
                    backend=default_backend())
            public_key_u2f = _encode_public_key(user_ec)

            # Step 5.
            #
            # Let verificationData be the concatenation of (0x00 || rpIdHash ||
            # clientDataHash || credentialId || publicKeyU2F) (see Section 4.3
            # of [FIDO-U2F-Message-Formats]).
            auth_data_rp_id_hash = _get_auth_data_rp_id_hash(auth_data)
            signature = att_stmt['sig']
            verification_data = ''.join([
                '\0',
                auth_data_rp_id_hash,
                client_data_hash,
                cred_id,
                public_key_u2f])

            # Step 6.
            #
            # Verify the sig using verificationData and certificate public
            # key per [SEC1].
            try:
                certificate_public_key.verify(signature, verification_data, ECDSA(SHA256()))
            except InvalidSignature:
                raise RegistrationRejectedException('Invalid signature received.')

            # Step 7.
            #
            # If successful, return attestation type Basic with the
            # attestation trust path set to x5c.
            attestation_type = AT_BASIC
            trust_path = [x509_att_cert]
            return (attestation_type, trust_path, public_key_u2f, cred_id)
        elif fmt == 'none':
            # `none` - indicates that the Relying Party is not interested in
            # authenticator attestation.
            if not self.none_attestation_permitted:
                raise RegistrationRejectedException('Authenticator attestation is required.')

            attestation_data = auth_data[37:]
            credential_id_len = struct.unpack('!H', attestation_data[16:18])[0]
            cred_id = attestation_data[18:18 + credential_id_len]
            credential_pub_key = attestation_data[18 + credential_id_len:]

            cpk = cbor2.loads(credential_pub_key)

            alg_key = 3
            x_key = -2
            y_key = -3

            if alg_key not in cpk:
                raise RegistrationRejectedException(
                    "Credential public key missing required algorithm parameter.")

            required_keys = {alg_key, x_key, y_key}
            cpk_keys = cpk.keys()

            if not set(cpk_keys).issuperset(required_keys):
                raise RegistrationRejectedException(
                    'Credential public key must match COSE_Key spec.')

            public_key_u2f = ''

            x = cpk[x_key].encode('hex')
            if len(x) != 64:
                raise RegistrationRejectedException('Bad public key.')
            x_long = long(x, 16)

            y = cpk[y_key].encode('hex')
            if len(y) != 64:
                raise RegistrationRejectedException('Bad public key.')
            y_long = long(y, 16)

            ES256 = -7
            if cpk[alg_key] != ES256:
                raise RegistrationRejectedException('Unsupported algorithm.')

            user_ec = EllipticCurvePublicNumbers(
                x_long, y_long,
                SECP256R1()).public_key(
                    backend=default_backend())
            public_key_u2f = _encode_public_key(user_ec)

            # Step 1.
            #
            # Return attestation type None with an empty trust path.
            attestation_type = AT_NONE
            trust_path = []
            return (attestation_type, trust_path, public_key_u2f, cred_id)
        else:
            raise RegistrationRejectedException('Invalid format.')

    def verify(self):
        try:
            # Step 1.
            #
            # Let JSONtext be the result of running UTF-8 decode on the value of
            # response.clientDataJSON.
            json_text = self.registration_response.get('clientData', '').decode('utf-8')

            # Step 2.
            #
            # Let C, the client data claimed as collected during the credential
            # creation, be the result of running an implementation-specific JSON
            # parser on JSONtext.
            decoded_cd = _webauthn_b64_decode(json_text)
            c = json.loads(decoded_cd)

            credential_id = self.registration_response.get('id')
            raw_id = self.registration_response.get('rawId')
            attestation_object = self.registration_response.get('attObj')
            credential_type = self.registration_response.get('type')

            # Step 3.
            #
            # Verify that the value of C.type is webauthn.create.
            received_type = c.get('type')
            if not _verify_type(received_type, TYPE_CREATE):
                raise RegistrationRejectedException('Invalid type.')

            # Step 4.
            #
            # Verify that the value of C.challenge matches the challenge that was sent
            # to the authenticator in the create() call.
            received_challenge = c.get('challenge')
            if not _verify_challenge(received_challenge, self.challenge):
                raise RegistrationRejectedException('Unable to verify challenge.')

            # Step 5.
            #
            # Verify that the value of C.origin matches the Relying Party's origin.
            if not _verify_origin(c, self.origin):
                raise RegistrationRejectedException('Unable to verify origin.')

            # Step 6.
            #
            # Verify that the value of C.tokenBinding.status matches the state of
            # Token Binding for the TLS connection over which the assertion was
            # obtained. If Token Binding was used on that TLS connection, also verify
            # that C.tokenBinding.id matches the base64url encoding of the Token
            # Binding ID for the connection.

            # XXX: Chrome does not currently supply token binding in the clientDataJSON
            # if not _verify_token_binding_id(c):
            #    raise RegistrationRejectedException('Unable to verify token binding ID.')

            # Step 7.
            #
            # Compute the hash of response.clientDataJSON using SHA-256.
            client_data_hash = _get_client_data_hash(decoded_cd)

            # Step 8.
            #
            # Perform CBOR decoding on the attestationObject field of
            # the AuthenticatorAttestationResponse structure to obtain
            # the attestation statement format fmt, the authenticator
            # data authData, and the attestation statement attStmt.
            att_obj = cbor2.loads(_webauthn_b64_decode(attestation_object))
            att_stmt = att_obj.get('attStmt')
            auth_data = att_obj.get('authData')
            fmt = att_obj.get('fmt')
            if not auth_data or len(auth_data) < 37:
                raise RegistrationRejectedException('Auth data must be at least 37 bytes.')

            # Step 9.
            #
            # Verify that the RP ID hash in authData is indeed the
            # SHA-256 hash of the RP ID expected by the RP.
            auth_data_rp_id_hash = _get_auth_data_rp_id_hash(auth_data)
            if not _verify_rp_id_hash(auth_data_rp_id_hash, self.rp_id):
                raise RegistrationRejectedException('Unable to verify RP ID hash.')

            # Step 10.
            #
            # If user verification is required for this registration,
            # verify that the User Verified bit of the flags in authData
            # is set.

            # Authenticator data flags.
            # https://www.w3.org/TR/webauthn/#authenticator-data
            flags = struct.unpack('!B', auth_data[32])[0]

            if (self.uv_required and (flags & const.USER_VERIFIED) != 0x04):
                raise RegistrationRejectedException('Malformed request received.')

            # Step 11.
            #
            # If user verification is not required for this registration,
            # verify that the User Present bit of the flags in authData
            # is set.
            if (not self.uv_required and (flags & const.USER_PRESENT) != 0x01):
                raise RegistrationRejectedException('Malformed request received.')

            # Step 12.
            #
            # Verify that the values of the client extension outputs in
            # clientExtensionResults and the authenticator extension outputs
            # in the extensions in authData are as expected, considering the
            # client extension input values that were given as the extensions
            # option in the create() call. In particular, any extension
            # identifier values in the clientExtensionResults and the extensions
            # in authData MUST be also be present as extension identifier values
            # in the extensions member of options, i.e., no extensions are
            # present that were not requested. In the general case, the meaning
            # of "are as expected" is specific to the Relying Party and which
            # extensions are in use.
            registration_client_extensions = self.registration_response.get(
                'registrationClientExtensions')
            rce = json.loads(registration_client_extensions)
            if not _verify_client_extensions(rce):
                raise RegistrationRejectedException('Unable to verify client extensions.')
            if not _verify_authenticator_extensions(c):
                raise RegistrationRejectedException('Unable to verify authenticator extensions.')

            # Step 13.
            #
            # Determine the attestation statement format by performing
            # a USASCII case-sensitive match on fmt against the set of
            # supported WebAuthn Attestation Statement Format Identifier
            # values. The up-to-date list of registered WebAuthn
            # Attestation Statement Format Identifier values is maintained
            # in the in the IANA registry of the same name
            # [WebAuthn-Registries].
            if not _verify_attestation_statement_format(fmt):
                raise RegistrationRejectedException(
                    'Unable to verify attestation statement format.')

            # Step 14.
            #
            # Verify that attStmt is a correct attestation statement, conveying
            # a valid attestation signature, by using the attestation statement
            # format fmt's verification procedure given attStmt, authData and
            # the hash of the serialized client data computed in step 7.
            (attestation_type,
                trust_path,
                credential_public_key,
                cred_id) = self._verify_attestation_statement(
                    fmt, att_stmt, auth_data, client_data_hash)

            # Step 15.
            #
            # If validation is successful, obtain a list of acceptable trust
            # anchors (attestation root certificates or ECDAA-Issuer public
            # keys) for that attestation type and attestation statement format
            # fmt, from a trusted source or from policy. For example, the FIDO
            # Metadata Service [FIDOMetadataService] provides one way to obtain
            # such information, using the aaguid in the attestedCredentialData
            # in authData.
            trust_anchors = _get_trust_anchors(attestation_type, fmt, self.trust_anchor_dir)
            if not trust_anchors and self.trusted_attestation_cert_required:
                raise RegistrationRejectedException(
                    'No trust anchors available to verify attestation certificate.')

            # Step 16.
            #
            # Assess the attestation trustworthiness using the outputs of the
            # verification procedure in step 14, as follows:
            #
            #     * If self attestation was used, check if self attestation is
            #       acceptable under Relying Party policy.
            #     * If ECDAA was used, verify that the identifier of the
            #       ECDAA-Issuer public key used is included in the set of
            #       acceptable trust anchors obtained in step 15.
            #     * Otherwise, use the X.509 certificates returned by the
            #       verification procedure to verify that the attestation
            #       public key correctly chains up to an acceptable root
            #       certificate.
            if attestation_type == AT_SELF_ATTESTATION:
                if not self.self_attestation_permitted:
                    raise RegistrationRejectedException('Self attestation is not permitted.')
            elif attestation_type == AT_ATTESTATION_CA:
                raise NotImplementedError(
                    'Attestation CA attestation type is not currently supported.')
            elif attestation_type == AT_ECDAA:
                raise NotImplementedError(
                    'ECDAA attestation type is not currently supported.')
            elif attestation_type == AT_BASIC:
                if self.trusted_attestation_cert_required:
                    if not _is_trusted_attestation_cert(trust_path, trust_anchors):
                        raise RegistrationRejectedException(
                            'Untrusted attestation certificate.')
            else:
                raise RegistrationRejectedException('Unknown attestation type.')

            # Step 17.
            #
            # Check that the credentialId is not yet registered to any other user.
            # If registration is requested for a credential that is already registered
            # to a different user, the Relying Party SHOULD fail this registration
            # ceremony, or it MAY decide to accept the registration, e.g. while deleting
            # the older registration.
            #
            # NOTE: This needs to be done by the Relying Party by checking the
            #       `credential_id` property of `WebAuthnCredential` against their
            #       database. See `flask_demo/app.py`.

            # Step 18.
            #
            # If the attestation statement attStmt verified successfully and is
            # found to be trustworthy, then register the new credential with the
            # account that was denoted in the options.user passed to create(),
            # by associating it with the credentialId and credentialPublicKey in
            # the attestedCredentialData in authData, as appropriate for the
            # Relying Party's system.

            # Step 19.
            #
            # If the attestation statement attStmt successfully verified but is
            # not trustworthy per step 16 above, the Relying Party SHOULD fail
            # the registration ceremony.
            #
            #     NOTE: However, if permitted by policy, the Relying Party MAY
            #           register the credential ID and credential public key but
            #           treat the credential as one with self attestation (see
            #           6.3.3 Attestation Types). If doing so, the Relying Party
            #           is asserting there is no cryptographic proof that the
            #           public key credential has been generated by a particular
            #           authenticator model. See [FIDOSecRef] and [UAFProtocol]
            #           for a more detailed discussion.

            sc = auth_data[33:37]
            sign_count = struct.unpack('!I', sc)[0]

            credential = WebAuthnCredential(
                self.rp_id,
                self.origin,
                _webauthn_b64_encode(cred_id),
                _webauthn_b64_encode(credential_public_key),
                sign_count)

            return credential

        except Exception as e:
            raise RegistrationRejectedException(
                'Registration rejected. Error: {}.'.format(e))


class WebAuthnAssertionResponse(object):

    def __init__(self,
                 webauthn_user,
                 assertion_response,
                 challenge,
                 origin,
                 allow_credentials=None,
                 uv_required=False):
        self.webauthn_user = webauthn_user
        self.assertion_response = assertion_response
        self.challenge = challenge
        self.origin = origin
        self.allow_credentials = allow_credentials
        self.uv_required = uv_required

    def verify(self):
        try:
            # Step 1.
            #
            # If the allowCredentials option was given when this authentication
            # ceremony was initiated, verify that credential.id identifies one
            # of the public key credentials that were listed in allowCredentials.
            cid = self.assertion_response.get('id')
            if self.allow_credentials:
                if cid not in self.allow_credentials:
                    raise AuthenticationRejectedException('Invalid credential.')

            # Step 2.
            #
            # If credential.response.userHandle is present, verify that the user
            # identified by this value is the owner of the public key credential
            # identified by credential.id.
            user_handle = self.assertion_response.get('userHandle')
            if user_handle:
                if not user_handle == self.webauthn_user.username:
                    raise AuthenticationRejectedException('Invalid credential.')

            # Step 3.
            #
            # Using credential's id attribute (or the corresponding rawId, if
            # base64url encoding is inappropriate for your use case), look up
            # the corresponding credential public key.
            if not _validate_credential_id(self.webauthn_user.credential_id):
                raise AuthenticationRejectedException('Invalid credential ID.')

            if not isinstance(self.webauthn_user, WebAuthnUser):
                raise AuthenticationRejectedException('Invalid user type.')

            credential_public_key = self.webauthn_user.public_key
            decoded_user_pub_key = _decode_public_key(
                _webauthn_b64_decode(credential_public_key))
            user_pubkey = decoded_user_pub_key.public_key(backend=default_backend())

            # Step 4.
            #
            # Let cData, aData and sig denote the value of credential's
            # response's clientDataJSON, authenticatorData, and signature
            # respectively.
            c_data = self.assertion_response.get('clientData')
            a_data = self.assertion_response.get('authData')
            decoded_a_data = _webauthn_b64_decode(a_data)
            sig = self.assertion_response.get('signature').decode('hex')

            # Step 5.
            #
            # Let JSONtext be the result of running UTF-8 decode on the
            # value of cData.
            json_text = c_data.decode('utf-8')

            # Step 6.
            #
            # Let C, the client data claimed as used for the signature,
            # be the result of running an implementation-specific JSON
            # parser on JSONtext.
            decoded_cd = _webauthn_b64_decode(json_text)
            c = json.loads(decoded_cd)

            # Step 7.
            #
            # Verify that the value of C.type is the string webauthn.get.
            received_type = c.get('type')
            if not _verify_type(received_type, TYPE_GET):
                raise RegistrationRejectedException('Invalid type.')

            # Step 8.
            #
            # Verify that the value of C.challenge matches the challenge
            # that was sent to the authenticator in the
            # PublicKeyCredentialRequestOptions passed to the get() call.
            received_challenge = c.get('challenge')
            if not _verify_challenge(received_challenge, self.challenge):
                raise AuthenticationRejectedException('Unable to verify challenge.')

            # Step 9.
            #
            # Verify that the value of C.origin matches the Relying
            # Party's origin.
            if not _verify_origin(c, self.origin):
                raise AuthenticationRejectedException('Unable to verify origin.')

            # Step 10.
            #
            # Verify that the value of C.tokenBinding.status matches
            # the state of Token Binding for the TLS connection over
            # which the attestation was obtained. If Token Binding was
            # used on that TLS connection, also verify that
            # C.tokenBinding.id matches the base64url encoding of the
            # Token Binding ID for the connection.

            # XXX: Chrome does not currently supply token binding in the clientDataJSON
            # if not _verify_token_binding_id(c):
            #     raise AuthenticationRejectedException('Unable to verify token binding ID.')

            # Step 11.
            #
            # Verify that the rpIdHash in aData is the SHA-256 hash of
            # the RP ID expected by the Relying Party.
            auth_data_rp_id_hash = _get_auth_data_rp_id_hash(decoded_a_data)
            if not _verify_rp_id_hash(auth_data_rp_id_hash, self.webauthn_user.rp_id):
                raise AuthenticationRejectedException('Unable to verify RP ID hash.')

            # Step 12.
            #
            # If user verification is required for this assertion, verify
            # that the User Verified bit of the flags in aData is set.

            # Authenticator data flags.
            # https://www.w3.org/TR/webauthn/#authenticator-data
            flags = struct.unpack('!B', decoded_a_data[32])[0]

            if (self.uv_required and (flags & const.USER_VERIFIED) != 0x04):
                raise AuthenticationRejectedException('Malformed request received.')

            # Step 13.
            #
            # If user verification is not required for this assertion, verify
            # that the User Present bit of the flags in aData is set.
            if (not self.uv_required and (flags & const.USER_PRESENT) != 0x01):
                raise AuthenticationRejectedException('Malformed request received.')

            # Step 14.
            #
            # Verify that the values of the client extension outputs in
            # clientExtensionResults and the authenticator extension outputs
            # in the extensions in authData are as expected, considering the
            # client extension input values that were given as the extensions
            # option in the get() call. In particular, any extension identifier
            # values in the clientExtensionResults and the extensions in
            # authData MUST be also be present as extension identifier values
            # in the extensions member of options, i.e., no extensions are
            # present that were not requested. In the general case, the meaning
            # of "are as expected" is specific to the Relying Party and which
            # extensions are in use.
            assertion_client_extensions = self.assertion_response.get(
                'assertionClientExtensions')
            ace = json.loads(assertion_client_extensions)
            if not _verify_client_extensions(ace):
                raise AuthenticationRejectedException('Unable to verify client extensions.')
            if not _verify_authenticator_extensions(c):
                raise AuthenticationRejectedException('Unable to verify authenticator extensions.')

            # Step 15.
            #
            # Let hash be the result of computing a hash over the cData
            # using SHA-256.
            client_data_hash = _get_client_data_hash(decoded_cd)

            # Step 16.
            #
            # Using the credential public key looked up in step 3, verify
            # that sig is a valid signature over the binary concatenation
            # of aData and hash.
            bytes_to_sign = ''.join([
                decoded_a_data,
                client_data_hash])
            try:
                user_pubkey.verify(sig, bytes_to_sign, ECDSA(SHA256()))
            except InvalidSignature:
                raise AuthenticationRejectedException('Invalid signature received.')

            # Step 17.
            #
            # If the signature counter value adata.signCount is nonzero or
            # the value stored in conjunction with credential's id attribute
            # is nonzero, then run the following sub-step:
            #     If the signature counter value adata.signCount is
            #         greater than the signature counter value stored in
            #         conjunction with credential's id attribute.
            #             Update the stored signature counter value,
            #             associated with credential's id attribute,
            #             to be the value of adata.signCount.
            #         less than or equal to the signature counter value
            #         stored in conjunction with credential's id attribute.
            #             This is a signal that the authenticator may be
            #             cloned, i.e. at least two copies of the credential
            #             private key may exist and are being used in parallel.
            #             Relying Parties should incorporate this information
            #             into their risk scoring. Whether the Relying Party
            #             updates the stored signature counter value in this
            #             case, or not, or fails the authentication ceremony
            #             or not, is Relying Party-specific.
            sc = decoded_a_data[33:37]
            sign_count = struct.unpack('!I', sc)[0]
            if sign_count or self.webauthn_user.sign_count:
                if sign_count <= self.webauthn_user.sign_count:
                    raise AuthenticationRejectedException('Duplicate authentication detected.')

            # Step 18.
            #
            # If all the above steps are successful, continue with the
            # authentication ceremony as appropriate. Otherwise, fail the
            # authentication ceremony.
            return sign_count

        except Exception as e:
            raise AuthenticationRejectedException(
                'Authentication rejected. Error: {}.'.format(e))


def _encode_public_key(public_key):
    '''Extracts the x, y coordinates from a public point on a Cryptography elliptic
    curve, packs them into a standard byte string representation, and returns
    them
    :param public_key: an EllipticCurvePublicKey object
    :return: a 65-byte string. decode_public_key().public_key() can invert this
    function.
    '''
    numbers = public_key.public_numbers()
    return '\x04' + '{:064x}{:064x}'.format(numbers.x, numbers.y).decode('hex')


def _decode_public_key(key_bytes):
    '''Decode a packed SECP256r1 public key into an EllipticCurvePublicKey
    '''

    # Parsing this structure by hand, following SEC1, section 2.3.4
    # An alternative is to hack on the OpenSSL CFFI bindings so we
    # can call EC_POINT_oct2point on the contents of key_bytes. Please
    # believe me when I say that this is much simpler - mainly because
    # we can make assumptions about /exactly/ which EC curve we're
    # using!)
    if key_bytes[0] != '\x04':
        raise AuthenticationRejectedException('XXX bad public key.')

    # x and y coordinates are each 32-bytes long, encoded as big-endian binary
    # strings. Without calling unsupported C API functions (i.e.
    # _PyLong_FromByteArray), converting to hex-encoding and then parsing
    # seems to be the simplest way to make these into python big-integers.
    curve = SECP256R1()
    x = long(key_bytes[1:33].encode('hex'), 16)
    y = long(key_bytes[33:].encode('hex'), 16)

    return EllipticCurvePublicNumbers(x, y, curve)


def _webauthn_b64_decode(encoded):
    '''WebAuthn specifies web-safe base64 encoding *without* padding.
    Python implementation requires padding. We'll add it and then
    decode'''
    # Ensure that this is encoded as ascii, not unicode.
    encoded = encoded.encode('ascii')
    # Add '=' until length is a multiple of 4 bytes, then decode.
    padding_len = (-len(encoded) % 4)
    encoded += '=' * padding_len
    return base64.urlsafe_b64decode(encoded)


def _webauthn_b64_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip('=')


def _get_trust_anchors(attestation_type,
                       attestation_fmt,
                       trust_anchor_dir):
    '''Return a list of trusted attestation root certificates.
    '''
    if attestation_type not in SUPPORTED_ATTESTATION_TYPES:
        return []
    if attestation_fmt not in SUPPORTED_ATTESTATION_FORMATS:
        return []

    if trust_anchor_dir == DEFAULT_TRUST_ANCHOR_DIR:
        ta_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            trust_anchor_dir)
    else:
        ta_dir = trust_anchor_dir

    trust_anchors = []

    if os.path.isdir(ta_dir):
        for ta_name in os.listdir(ta_dir):
            ta_path = os.path.join(ta_dir, ta_name)
            if os.path.isfile(ta_path):
                with open(ta_path, 'rb') as f:
                    pem_data = f.read().strip()
                    try:
                        pem = crypto.load_certificate(
                            crypto.FILETYPE_PEM, pem_data)
                        trust_anchors.append(pem)
                    except Exception:
                        pass

    return trust_anchors


def _is_trusted_attestation_cert(trust_path, trust_anchors):
    if not trust_path or not isinstance(trust_path, list):
        return False
    # NOTE: Only using the first attestation cert in the
    #       attestation trust path for now, but should be
    #       able to build a chain.
    attestation_cert = trust_path[0]
    store = crypto.X509Store()
    for _ta in trust_anchors:
        store.add_cert(_ta)
    store_ctx = crypto.X509StoreContext(store, attestation_cert)

    try:
        store_ctx.verify_certificate()
        return True
    except Exception as e:
        print('Unable to verify certificate: {}.'.format(e), file=sys.stderr)

    return False


def _verify_type(received_type, expected_type):
    if received_type == expected_type:
        return True

    return False


def _verify_challenge(received_challenge, sent_challenge):
    if not isinstance(received_challenge, six.string_types):
        return False
    if not isinstance(sent_challenge, six.string_types):
        return False
    if not received_challenge:
        return False
    if not sent_challenge:
        return False
    if sent_challenge != received_challenge:
        return False

    return True


def _verify_origin(client_data, origin):
    if not isinstance(client_data, dict):
        return False

    client_data_origin = client_data.get('origin')

    if not client_data_origin:
        return False
    if client_data_origin != origin:
        return False

    return True


def _verify_token_binding_id(client_data):
    '''The tokenBinding member contains information about the state of the
    Token Binding protocol used when communicating with the Relying Party.
    The status member is one of:

        not-supported: when the client does not support token binding.

            supported: the client supports token binding, but it was not
                       negotiated when communicating with the Relying
                       Party.

              present: token binding was used when communicating with the
                       Relying Party. In this case, the id member MUST be
                       present and MUST be a base64url encoding of the
                       Token Binding ID that was used.
    '''
    # TODO: Add support for verifying token binding ID.
    token_binding_status = client_data['tokenBinding']['status']
    token_binding_id = client_data['tokenBinding'].get('id', '')
    if token_binding_status in ('supported', 'not-supported'):
        return True
    return False


def _verify_client_extensions(client_extensions):
    if set(EXPECTED_CLIENT_EXTENSIONS.keys()).issuperset(client_extensions.keys()):
        return True
    return False


def _verify_authenticator_extensions(client_data):
    # TODO
    return True


def _verify_rp_id_hash(auth_data_rp_id_hash, rp_id):
    rp_id_hash = hashlib.sha256(rp_id).digest()

    return auth_data_rp_id_hash == rp_id_hash


def _verify_attestation_statement_format(fmt):
    # TODO: Handle other attestation statement formats.
    '''Verify the attestation statement format.

    Currently only supporting 'fido-u2f'
    and 'none' attestation statement formats.
    '''
    if not isinstance(fmt, six.string_types):
        return False
    return fmt == 'none' or fmt == 'fido-u2f'


def _get_auth_data_rp_id_hash(auth_data):
    if not isinstance(auth_data, six.string_types):
        return False

    auth_data_rp_id_hash = auth_data[:32]

    return auth_data_rp_id_hash


def _get_client_data_hash(decoded_client_data):
    if not isinstance(decoded_client_data, six.string_types):
        return ''

    return hashlib.sha256(decoded_client_data).digest()


def _validate_credential_id(credential_id):
    if not isinstance(credential_id, six.string_types):
        return False

    return True
