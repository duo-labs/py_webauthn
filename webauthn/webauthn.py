# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import absolute_import

import base64
import hashlib
import json
import os
import struct
import sys
import binascii
import codecs

from builtins import bytes, int

import cbor2
import six

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA, EllipticCurvePublicNumbers, SECP256R1)
from cryptography.hazmat.primitives.asymmetric.padding import (MGF1, PKCS1v15,
                                                               PSS)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509 import load_der_x509_certificate
from OpenSSL import crypto

from . import const

# Only supporting 'None', 'Basic', and 'Self Attestation' attestation types for now.
AT_BASIC = 'Basic'
AT_ECDAA = 'ECDAA'
AT_NONE = 'None'
AT_ATTESTATION_CA = 'AttCA'
AT_SELF_ATTESTATION = 'Self'

SUPPORTED_ATTESTATION_TYPES = (AT_BASIC, AT_NONE, AT_SELF_ATTESTATION)

AT_FMT_FIDO_U2F = 'fido-u2f'
AT_FMT_PACKED = 'packed'
AT_FMT_NONE = 'none'

# Only supporting 'fido-u2f', 'packed', and 'none' attestation formats for now.
SUPPORTED_ATTESTATION_FORMATS = (AT_FMT_FIDO_U2F, AT_FMT_PACKED, AT_FMT_NONE)

COSE_ALG_ES256 = -7
COSE_ALG_PS256 = -37
COSE_ALG_RS256 = -257

# Trust anchors (trusted attestation roots directory).
DEFAULT_TRUST_ANCHOR_DIR = 'trusted_attestation_roots'

# Client data type.
TYPE_CREATE = 'webauthn.create'
TYPE_GET = 'webauthn.get'

# Default client extensions
DEFAULT_CLIENT_EXTENSIONS = {'appid': None, 'loc': None}

# Default authenticator extensions
DEFAULT_AUTHENTICATOR_EXTENSIONS = {}


class COSEKeyException(Exception):
    pass


class AuthenticationRejectedException(Exception):
    pass


class RegistrationRejectedException(Exception):
    pass


class WebAuthnUserDataMissing(Exception):
    pass


class WebAuthnMakeCredentialOptions(object):

    _attestation_forms = {'none', 'indirect', 'direct'}
    _user_verification = {'required', 'preferred', 'discouraged'}

    def __init__(self, challenge, rp_name, rp_id, user_id, username,
                 display_name, icon_url, timeout=60000, attestation='direct',
                 user_verification=None):
        self.challenge = challenge
        self.rp_name = rp_name
        self.rp_id = rp_id
        self.user_id = user_id
        self.username = username
        self.display_name = display_name
        self.icon_url = icon_url
        self.timeout = timeout

        attestation = str(attestation).lower()
        if attestation not in self._attestation_forms:
            raise ValueError('Attestation must be a string and one of ' +
                             ', '.join(self._attestation_forms))
        self.attestation = attestation

        if user_verification is not None:
            user_verification = str(user_verification).lower()
            if user_verification not in self._user_verification:
                raise ValueError('user_verification must be a string and one of ' +
                                 ', '.join(self._user_verification))
        self.user_verification = user_verification

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
                'displayName': self.display_name
            },
            'pubKeyCredParams': [{
                'alg': COSE_ALG_ES256,
                'type': 'public-key',
            }, {
                'alg': COSE_ALG_RS256,
                'type': 'public-key',
            }, {
                'alg': COSE_ALG_PS256,
                'type': 'public-key',
            }],
            'timeout': self.timeout,
            'excludeCredentials': [],
            # Relying Parties may use AttestationConveyancePreference to specify their
            # preference regarding attestation conveyance during credential generation.
            'attestation': self.attestation,
            'extensions': {
                # Include location information in attestation.
                'webauthn.loc': True
            }
        }

        if self.user_verification is not None:
            registration_dict['authenticatorSelection'] = {
                'userVerification': self.user_verification
            }

        if self.icon_url:
            registration_dict['user']['icon'] = self.icon_url

        return registration_dict

    @property
    def json(self):
        return json.dumps(self.registration_dict)


class WebAuthnAssertionOptions(object):
    def __init__(self, webauthn_user, challenge, timeout=60000, userVerification='discouraged'):
        if isinstance(webauthn_user, list):
            self.webauthn_users = webauthn_user
        else:
            self.webauthn_users = [webauthn_user]
        self.challenge = challenge
        self.timeout = timeout
        self.userVerification = userVerification

    @property
    def assertion_dict(self):
        if not isinstance(self.webauthn_users, list) or len(self.webauthn_users) < 1:
            raise AuthenticationRejectedException('Invalid user list.')
        if len(set([u.rp_id for u in self.webauthn_users])) != 1:
            raise AuthenticationRejectedException('Invalid (mutliple) RP IDs in user list.')
        for user in self.webauthn_users:
            if not isinstance(user, WebAuthnUser):
                raise AuthenticationRejectedException('Invalid user type.')
            if not user.credential_id:
                raise AuthenticationRejectedException('Invalid credential ID.')
        if not self.challenge:
            raise AuthenticationRejectedException('Invalid challenge.')

        acceptable_credentials = []
        for user in self.webauthn_users:
            acceptable_credentials.append({
                'type': 'public-key',
                'id': user.credential_id,
                'transports': ['usb', 'nfc', 'ble', 'internal'],
            })

        assertion_dict = {
            'challenge': self.challenge,
            'allowCredentials': acceptable_credentials,
            'rpId': self.webauthn_users[0].rp_id,
            'timeout': self.timeout,
            'userVerification': self.userVerification,
            # 'extensions': {}
        }

        return assertion_dict

    @property
    def json(self):
        return json.dumps(self.assertion_dict)


class WebAuthnUser(object):
    def __init__(self, user_id, username, display_name, icon_url,
                 credential_id, public_key, sign_count, rp_id):

        if not credential_id:
            raise WebAuthnUserDataMissing("credential_id missing")

        if not rp_id:
            raise WebAuthnUserDataMissing("rp_id missing")

        self.user_id = user_id
        self.username = username
        self.display_name = display_name
        self.icon_url = icon_url
        self.credential_id = credential_id
        self.public_key = public_key
        self.sign_count = sign_count
        self.rp_id = rp_id

    def __str__(self):
        return '{} ({}, {}, {})'.format(self.user_id, self.username,
                                        self.display_name, self.sign_count)


class WebAuthnCredential(object):
    def __init__(self, rp_id, origin, credential_id, public_key, sign_count):
        self.rp_id = rp_id
        self.origin = origin
        self.credential_id = credential_id
        self.public_key = public_key
        self.sign_count = sign_count

    def __str__(self):
        return '{} ({}, {}, {})'.format(self.credential_id, self.rp_id,
                                        self.origin, self.sign_count)


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
                 uv_required=False,
                 expected_registration_client_extensions=DEFAULT_CLIENT_EXTENSIONS,
                 expected_registration_authenticator_extensions=DEFAULT_AUTHENTICATOR_EXTENSIONS):
        self.rp_id = rp_id
        self.origin = origin
        self.registration_response = registration_response
        self.challenge = challenge
        self.trust_anchor_dir = trust_anchor_dir
        self.trusted_attestation_cert_required = trusted_attestation_cert_required
        self.uv_required = uv_required
        self.expected_registration_client_extensions = expected_registration_client_extensions
        self.expected_registration_authenticator_extensions = \
            expected_registration_authenticator_extensions

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

    def _verify_attestation_statement(self, fmt, att_stmt, auth_data,
                                      client_data_hash):
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

        attestation_data = auth_data[37:]
        aaguid = attestation_data[:16]
        credential_id_len = struct.unpack('!H', attestation_data[16:18])[0]
        cred_id = attestation_data[18:18 + credential_id_len]
        credential_pub_key = attestation_data[18 + credential_id_len:]

        if fmt == AT_FMT_FIDO_U2F:
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
            x509_att_cert = load_der_x509_certificate(att_cert,
                                                      default_backend())
            certificate_public_key = x509_att_cert.public_key()
            if not isinstance(certificate_public_key.curve, SECP256R1):
                raise RegistrationRejectedException(
                    'Bad certificate public key.')

            # Step 3.
            #
            # Extract the claimed rpIdHash from authenticatorData, and the
            # claimed credentialId and credentialPublicKey from
            # authenticatorData.attestedCredentialData.

            # The credential public key encoded in COSE_Key format, as defined in Section 7
            # of [RFC8152], using the CTAP2 canonical CBOR encoding form. The COSE_Key-encoded
            # credential public key MUST contain the optional "alg" parameter and MUST NOT
            # contain any other optional parameters. The "alg" parameter MUST contain a
            # COSEAlgorithmIdentifier value. The encoded credential public key MUST also
            # contain any additional required parameters stipulated by the relevant key type
            # specification, i.e., required for the key type "kty" and algorithm "alg" (see
            # Section 8 of [RFC8152]).
            try:
                public_key_alg, credential_public_key = _load_cose_public_key(
                    credential_pub_key)
            except COSEKeyException as e:
                raise RegistrationRejectedException(str(e))

            public_key_u2f = _encode_public_key(credential_public_key)

            # Step 5.
            #
            # Let verificationData be the concatenation of (0x00 || rpIdHash ||
            # clientDataHash || credentialId || publicKeyU2F) (see Section 4.3
            # of [FIDO-U2F-Message-Formats]).
            auth_data_rp_id_hash = _get_auth_data_rp_id_hash(auth_data)
            alg = COSE_ALG_ES256
            signature = att_stmt['sig']
            verification_data = b''.join([
                b'\0', auth_data_rp_id_hash, client_data_hash, cred_id,
                public_key_u2f
            ])

            # Step 6.
            #
            # Verify the sig using verificationData and certificate public
            # key per [SEC1].
            try:
                _verify_signature(certificate_public_key, alg,
                                  verification_data, signature)
            except InvalidSignature:
                raise RegistrationRejectedException(
                    'Invalid signature received.')
            except NotImplementedError:
                raise RegistrationRejectedException('Unsupported algorithm.')

            # Step 7.
            #
            # If successful, return attestation type Basic with the
            # attestation trust path set to x5c.
            attestation_type = AT_BASIC
            trust_path = [x509_att_cert]

            return (attestation_type, trust_path, credential_pub_key, cred_id)
        elif fmt == AT_FMT_PACKED:
            attestation_syntaxes = {
                AT_BASIC: set(['alg', 'x5c', 'sig']),
                AT_ECDAA: set(['alg', 'sig', 'ecdaaKeyId']),
                AT_SELF_ATTESTATION: set(['alg', 'sig'])
            }

            # Step 1.
            #
            # Verify that attStmt is valid CBOR conforming to the syntax
            # defined above and perform CBOR decoding on it to extract the
            # contained fields.
            if set(att_stmt.keys()) not in attestation_syntaxes.values():
                raise RegistrationRejectedException(
                    'Attestation statement must be a valid CBOR object.')

            alg = att_stmt['alg']
            signature = att_stmt['sig']
            verification_data = b''.join([auth_data, client_data_hash])

            if 'x5c' in att_stmt:
                # Step 2.
                #
                # If x5c is present, this indicates that the attestation
                # type is not ECDAA. In this case:
                att_cert = att_stmt['x5c'][0]
                x509_att_cert = load_der_x509_certificate(
                    att_cert, default_backend())
                certificate_public_key = x509_att_cert.public_key()

                #   * Verify that sig is a valid signature over the
                #     concatenation of authenticatorData and clientDataHash
                #     using the attestation public key in attestnCert with
                #     the algorithm specified in alg.
                try:
                    _verify_signature(certificate_public_key, alg,
                                      verification_data, signature)
                except InvalidSignature:
                    raise RegistrationRejectedException(
                        'Invalid signature received.')
                except NotImplementedError:
                    raise RegistrationRejectedException(
                        'Unsupported algorithm.')

                #   * Verify that attestnCert meets the requirements in
                #     §8.2.1 Packed attestation statement certificate
                #     requirements.

                # The attestation certificate MUST have the following
                # fields/extensions:
                #   * Version MUST be set to 3 (which is indicated by an
                #     ASN.1 INTEGER with value 2).
                if x509_att_cert.version != x509.Version.v3:
                    raise RegistrationRejectedException(
                        'Invalid attestation certificate version.')

                #   * Subject field MUST be set to:
                subject = x509_att_cert.subject
                COUNTRY_NAME = x509.NameOID.COUNTRY_NAME
                ORGANIZATION_NAME = x509.NameOID.ORGANIZATION_NAME
                ORG_UNIT_NAME = x509.NameOID.ORGANIZATIONAL_UNIT_NAME
                COMMON_NAME = x509.NameOID.COMMON_NAME

                #     * Subject-C: ISO 3166 code specifying the country
                #                  where the Authenticator vendor is
                #                  incorporated
                if not subject.get_attributes_for_oid(COUNTRY_NAME):
                    raise RegistrationRejectedException(
                        'Attestation certificate must have subject-C.')

                #     * Subject-O: Legal name of the Authenticator vendor
                if not subject.get_attributes_for_oid(ORGANIZATION_NAME):
                    raise RegistrationRejectedException(
                        'Attestation certificate must have subject-O.')

                #     * Subject-OU: Literal string
                #                   “Authenticator Attestation”
                ou = subject.get_attributes_for_oid(ORG_UNIT_NAME)
                if not ou or ou[0].value != 'Authenticator Attestation':
                    raise RegistrationRejectedException(
                        "Attestation certificate must have subject-OU set to "
                        "'Authenticator Attestation'.")

                #     * Subject-CN: A UTF8String of the vendor’s choosing
                if not subject.get_attributes_for_oid(COMMON_NAME):
                    raise RegistrationRejectedException(
                        'Attestation certificate must have subject-CN.')

                extensions = x509_att_cert.extensions

                #   * If the related attestation root certificate is used
                #     for multiple authenticator models, the Extension OID
                #     1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST
                #     be present, containing the AAGUID as a 16-byte OCTET
                #     STRING. The extension MUST NOT be marked as critical.
                try:
                    oid = x509.ObjectIdentifier('1.3.6.1.4.1.45724.1.1.4')
                    aaguid_ext = extensions.get_extension_for_oid(oid)
                    if aaguid_ext.value.value[2:] != aaguid:
                        raise RegistrationRejectedException(
                            'Attestation certificate AAGUID must match '
                            'authenticator data.')
                    if aaguid_ext.critical:
                        raise RegistrationRejectedException(
                            "Attestation certificate's "
                            "'id-fido-gen-ce-aaguid' extension must not be "
                            "marked critical.")
                except x509.ExtensionNotFound:
                    pass  # Optional extension

                #   * The Basic Constraints extension MUST have the CA
                #     component set to false.
                bc_extension = extensions.get_extension_for_class(
                    x509.BasicConstraints)
                if not bc_extension or bc_extension.value.ca:
                    raise RegistrationRejectedException(
                        'Attestation certificate must have Basic Constraints '
                        'extension with CA=false.')

                #   * If successful, return attestation type Basic and
                #     attestation trust path x5c.
                attestation_type = AT_BASIC
                trust_path = [x509_att_cert]
            elif 'ecdaaKeyId' in att_stmt:
                # Step 3.
                #
                # If ecdaaKeyId is present, then the attestation type is
                # ECDAA. In this case:
                #   * Verify that sig is a valid signature over the
                #     concatenation of authenticatorData and clientDataHash
                #     using ECDAA-Verify with ECDAA-Issuer public key
                #     identified by ecdaaKeyId (see  [FIDOEcdaaAlgorithm]).
                #   * If successful, return attestation type ECDAA and
                #     attestation trust path ecdaaKeyId.
                raise RegistrationRejectedException(
                    'ECDAA attestation type is not currently supported.')
            else:
                # Step 4.
                #
                # If neither x5c nor ecdaaKeyId is present, self
                # attestation is in use.
                #   * Validate that alg matches the algorithm of the
                #     credentialPublicKey in authenticatorData.
                try:
                    public_key_alg, credential_public_key = _load_cose_public_key(
                        credential_pub_key)
                except COSEKeyException as e:
                    raise RegistrationRejectedException(str(e))

                if public_key_alg != alg:
                    raise RegistrationRejectedException(
                        'Public key algorithm does not match.')

                #   * Verify that sig is a valid signature over the
                #     concatenation of authenticatorData and clientDataHash
                #     using the credential public key with alg.
                try:
                    _verify_signature(credential_public_key, alg,
                                      verification_data, signature)
                except InvalidSignature:
                    raise RegistrationRejectedException(
                        'Invalid signature received.')
                except NotImplementedError:
                    raise RegistrationRejectedException(
                        'Unsupported algorithm.')

                #   * If successful, return attestation type Self and empty
                #     attestation trust path.
                attestation_type = AT_SELF_ATTESTATION
                trust_path = []

            return (attestation_type, trust_path, credential_pub_key, cred_id)
        elif fmt == AT_FMT_NONE:
            # `none` - indicates that the Relying Party is not interested in
            # authenticator attestation.
            if not self.none_attestation_permitted:
                raise RegistrationRejectedException(
                    'Authenticator attestation is required.')

            # Step 1.
            #
            # Return attestation type None with an empty trust path.
            attestation_type = AT_NONE
            trust_path = []
            return (attestation_type, trust_path, credential_pub_key, cred_id)
        else:
            raise RegistrationRejectedException('Invalid format.')

    def verify(self):
        try:
            # Step 1.
            #
            # Let JSONtext be the result of running UTF-8 decode on the value of
            # response.clientDataJSON.

            json_text = self.registration_response.get('clientData', '')
            if sys.version_info < (3, 0):  # if python2
                json_text = json_text.decode('utf-8')

            # Step 2.
            #
            # Let C, the client data claimed as collected during the credential
            # creation, be the result of running an implementation-specific JSON
            # parser on JSONtext.
            decoded_cd = _webauthn_b64_decode(json_text)

            if sys.version_info < (3, 6):  # if json.loads doesn't support bytes
                c = json.loads(decoded_cd.decode('utf-8'))
            else:
                c = json.loads(decoded_cd)

            attestation_object = self.registration_response.get('attObj')

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
                raise RegistrationRejectedException(
                    'Unable to verify challenge.')

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
                raise RegistrationRejectedException(
                    'Auth data must be at least 37 bytes.')

            # Step 9.
            #
            # Verify that the RP ID hash in authData is indeed the
            # SHA-256 hash of the RP ID expected by the RP.
            auth_data_rp_id_hash = _get_auth_data_rp_id_hash(auth_data)
            # NOTE: In Python 3, `auth_data_rp_id_hash` will be bytes,
            # which is expected in `_verify_rp_id_hash()`.
            if not _verify_rp_id_hash(auth_data_rp_id_hash, self.rp_id):
                raise RegistrationRejectedException(
                    'Unable to verify RP ID hash.')

            # Step 10.
            #
            # Verify that the User Present bit of the flags in authData
            # is set.

            # Authenticator data flags.
            # https://www.w3.org/TR/webauthn/#authenticator-data
            flags = struct.unpack('!B', auth_data[32:33])[0]

            if (flags & const.USER_PRESENT) != 0x01:
                raise RegistrationRejectedException(
                    'Malformed request received.')

            # Step 11.
            #
            # If user verification is required for this registration, verify
            # that the User Verified bit of the flags in authData is set.
            if (self.uv_required and (flags & const.USER_VERIFIED) != 0x04):
                raise RegistrationRejectedException(
                    'Malformed request received.')

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
            if registration_client_extensions:
                rce = json.loads(registration_client_extensions)
                if not _verify_client_extensions(rce, self.expected_registration_client_extensions):
                    raise RegistrationRejectedException(
                        'Unable to verify client extensions.')
                if not _verify_authenticator_extensions(
                        c, self.expected_registration_authenticator_extensions):
                    raise RegistrationRejectedException(
                        'Unable to verify authenticator extensions.')

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
            (attestation_type, trust_path, credential_public_key,
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
            trust_anchors = _get_trust_anchors(attestation_type, fmt,
                                               self.trust_anchor_dir)
            if not trust_anchors and self.trusted_attestation_cert_required:
                raise RegistrationRejectedException(
                    'No trust anchors available to verify attestation certificate.'
                )

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
                    raise RegistrationRejectedException(
                        'Self attestation is not permitted.')
            elif attestation_type == AT_ATTESTATION_CA:
                raise NotImplementedError(
                    'Attestation CA attestation type is not currently supported.'
                )
            elif attestation_type == AT_ECDAA:
                raise NotImplementedError(
                    'ECDAA attestation type is not currently supported.')
            elif attestation_type == AT_BASIC:
                if self.trusted_attestation_cert_required:
                    if not _is_trusted_attestation_cert(
                            trust_path, trust_anchors):
                        raise RegistrationRejectedException(
                            'Untrusted attestation certificate.')
            elif attestation_type == AT_NONE:
                pass
            else:
                raise RegistrationRejectedException(
                    'Unknown attestation type.')

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
                self.rp_id, self.origin, _webauthn_b64_encode(cred_id),
                _webauthn_b64_encode(credential_public_key), sign_count)

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
                 uv_required=False,
                 expected_assertion_client_extensions=DEFAULT_CLIENT_EXTENSIONS,
                 expected_assertion_authenticator_extensions=DEFAULT_AUTHENTICATOR_EXTENSIONS):
        self.webauthn_user = webauthn_user
        self.assertion_response = assertion_response
        self.challenge = challenge
        self.origin = origin
        self.allow_credentials = allow_credentials
        self.uv_required = uv_required
        self.expected_assertion_client_extensions = expected_assertion_client_extensions
        self.expected_assertion_authenticator_extensions = \
            expected_assertion_authenticator_extensions

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
                    raise AuthenticationRejectedException(
                        'Invalid credential.')

            # Step 2.
            #
            # If credential.response.userHandle is present, verify that the user
            # identified by this value is the owner of the public key credential
            # identified by credential.id.
            if not self.webauthn_user.username:
                raise WebAuthnUserDataMissing("username missing")

            user_handle = self.assertion_response.get('userHandle')
            if user_handle:
                if not user_handle == self.webauthn_user.username:
                    raise AuthenticationRejectedException(
                        'Invalid credential.')

            # Step 3.
            #
            # Using credential's id attribute (or the corresponding rawId, if
            # base64url encoding is inappropriate for your use case), look up
            # the corresponding credential public key.
            if not _validate_credential_id(self.webauthn_user.credential_id):
                raise AuthenticationRejectedException('Invalid credential ID.')

            if not isinstance(self.webauthn_user, WebAuthnUser):
                raise AuthenticationRejectedException('Invalid user type.')

            if not self.webauthn_user.public_key:
                raise WebAuthnUserDataMissing("public_key missing")

            credential_public_key = self.webauthn_user.public_key
            public_key_alg, user_pubkey = _load_cose_public_key(
                _webauthn_b64_decode(credential_public_key))

            # Step 4.
            #
            # Let cData, aData and sig denote the value of credential's
            # response's clientDataJSON, authenticatorData, and signature
            # respectively.
            c_data = self.assertion_response.get('clientData')
            a_data = self.assertion_response.get('authData')
            decoded_a_data = _webauthn_b64_decode(a_data)
            sig = binascii.unhexlify(self.assertion_response.get('signature'))

            # Step 5.
            #
            # Let JSONtext be the result of running UTF-8 decode on the
            # value of cData.
            if sys.version_info < (3, 0):  # if python2
                json_text = c_data.decode('utf-8')
            else:
                json_text = c_data

            # Step 6.
            #
            # Let C, the client data claimed as used for the signature,
            # be the result of running an implementation-specific JSON
            # parser on JSONtext.
            decoded_cd = _webauthn_b64_decode(json_text)

            if sys.version_info < (3, 6):  # if json.loads doesn't support bytes
                c = json.loads(decoded_cd.decode('utf-8'))
            else:
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
                raise AuthenticationRejectedException(
                    'Unable to verify challenge.')

            # Step 9.
            #
            # Verify that the value of C.origin matches the Relying
            # Party's origin.
            if not _verify_origin(c, self.origin):
                raise AuthenticationRejectedException(
                    'Unable to verify origin.')

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
            if not _verify_rp_id_hash(auth_data_rp_id_hash,
                                      self.webauthn_user.rp_id):
                raise AuthenticationRejectedException(
                    'Unable to verify RP ID hash.')

            # Step 12.
            #
            # Verify that the User Present bit of the flags in authData
            # is set.

            # Authenticator data flags.
            # https://www.w3.org/TR/webauthn/#authenticator-data
            flags = struct.unpack('!B', decoded_a_data[32:33])[0]

            if (flags & const.USER_PRESENT) != 0x01:
                raise AuthenticationRejectedException(
                    'Malformed request received.')

            # Step 13.
            #
            # If user verification is required for this assertion, verify that
            # the User Verified bit of the flags in authData is set.
            if (self.uv_required and (flags & const.USER_VERIFIED) != 0x04):
                raise RegistrationRejectedException(
                    'Malformed request received.')

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
            if assertion_client_extensions:
                ace = json.loads(assertion_client_extensions)
                if not _verify_client_extensions(ace, self.expected_assertion_client_extensions):
                    raise AuthenticationRejectedException(
                        'Unable to verify client extensions.')
                if not _verify_authenticator_extensions(
                        c, self.expected_assertion_authenticator_extensions):
                    raise AuthenticationRejectedException(
                        'Unable to verify authenticator extensions.')

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
            bytes_to_verify = b''.join([decoded_a_data, client_data_hash])

            try:
                _verify_signature(user_pubkey, public_key_alg, bytes_to_verify,
                                  sig)
            except InvalidSignature:
                raise AuthenticationRejectedException(
                    'Invalid signature received.')
            except NotImplementedError:
                raise AuthenticationRejectedException('Unsupported algorithm.')

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
            
            if sign_count == 0 and self.webauthn_user.sign_count == 0:
                return 0
            
            if not sign_count:
                raise AuthenticationRejectedException('Unable to parse sign_count.')

            if (isinstance(self.webauthn_user.sign_count, int) and
                    self.webauthn_user.sign_count < 0) or not isinstance(
                        self.webauthn_user.sign_count, int):
                raise WebAuthnUserDataMissing('sign_count missing from WebAuthnUser.')

            if sign_count <= self.webauthn_user.sign_count:
                raise AuthenticationRejectedException(
                    'Duplicate authentication detected.')

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
    return b'\x04' + binascii.unhexlify('{:064x}{:064x}'.format(
        numbers.x, numbers.y))


def _load_cose_public_key(key_bytes):
    ALG_KEY = 3

    cose_public_key = cbor2.loads(key_bytes)

    if ALG_KEY not in cose_public_key:
        raise COSEKeyException(
            'Public key missing required algorithm parameter.')

    alg = cose_public_key[ALG_KEY]

    if alg == COSE_ALG_ES256:
        X_KEY = -2
        Y_KEY = -3

        required_keys = {ALG_KEY, X_KEY, Y_KEY}

        if not set(cose_public_key.keys()).issuperset(required_keys):
            raise COSEKeyException('Public key must match COSE_Key spec.')

        if len(cose_public_key[X_KEY]) != 32:
            raise RegistrationRejectedException('Bad public key.')
        x = int(codecs.encode(cose_public_key[X_KEY], 'hex'), 16)

        if len(cose_public_key[Y_KEY]) != 32:
            raise RegistrationRejectedException('Bad public key.')
        y = int(codecs.encode(cose_public_key[Y_KEY], 'hex'), 16)

        return alg, EllipticCurvePublicNumbers(
            x, y, SECP256R1()).public_key(backend=default_backend())
    elif alg in (COSE_ALG_PS256, COSE_ALG_RS256):
        E_KEY = -2
        N_KEY = -1

        required_keys = {ALG_KEY, E_KEY, N_KEY}

        if not set(cose_public_key.keys()).issuperset(required_keys):
            raise COSEKeyException('Public key must match COSE_Key spec.')

        if len(cose_public_key[E_KEY]) != 3 or len(cose_public_key[N_KEY]) != 256:
            raise COSEKeyException('Bad public key.')

        e = int(codecs.encode(cose_public_key[E_KEY], 'hex'), 16)
        n = int(codecs.encode(cose_public_key[N_KEY], 'hex'), 16)

        return alg, RSAPublicNumbers(e,
                                     n).public_key(backend=default_backend())
    else:
        raise COSEKeyException('Unsupported algorithm.')


def _webauthn_b64_decode(encoded):
    '''WebAuthn specifies web-safe base64 encoding *without* padding.
    Python implementation requires padding. We'll add it and then
    decode'''
    if sys.version_info < (3, 0):  # if python2
        # Ensure that this is encoded as ascii, not unicode.
        encoded = encoded.encode('ascii')
    else:
        if isinstance(encoded, bytes):
            encoded = str(encoded, 'utf-8')
    # Add '=' until length is a multiple of 4 bytes, then decode.
    padding_len = (-len(encoded) % 4)
    encoded += '=' * padding_len
    return base64.urlsafe_b64decode(encoded)


def _webauthn_b64_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b'=')


def _get_trust_anchors(attestation_type, attestation_fmt, trust_anchor_dir):
    '''Return a list of trusted attestation root certificates.
    '''
    if attestation_type not in SUPPORTED_ATTESTATION_TYPES:
        return []
    if attestation_fmt not in SUPPORTED_ATTESTATION_FORMATS:
        return []

    if trust_anchor_dir == DEFAULT_TRUST_ANCHOR_DIR:
        ta_dir = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), trust_anchor_dir)
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
                        pem = crypto.load_certificate(crypto.FILETYPE_PEM,
                                                      pem_data)
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
    if not constant_time.bytes_eq(
            bytes(sent_challenge, encoding='utf-8'),
            bytes(received_challenge, encoding='utf-8')):
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


def _verify_client_extensions(client_extensions, expected_client_extensions):
    if set(expected_client_extensions.keys()).issuperset(
            client_extensions.keys()):
        return True
    return False


def _verify_authenticator_extensions(client_data, expected_authenticator_extensions):
    # TODO
    return True


def _verify_rp_id_hash(auth_data_rp_id_hash, rp_id):
    if sys.version_info < (3, 0):  # if python2
        rp_id_hash = hashlib.sha256(rp_id).digest()
        return constant_time.bytes_eq(
            bytes(auth_data_rp_id_hash, encoding='utf-8'),
            bytes(rp_id_hash, encoding='utf-8'))
    else:
        rp_id_hash = hashlib.sha256(bytes(rp_id, "utf-8")).digest()
        return constant_time.bytes_eq(auth_data_rp_id_hash, rp_id_hash)


def _verify_attestation_statement_format(fmt):
    # TODO: Handle other attestation statement formats.
    '''Verify the attestation statement format.'''
    if not isinstance(fmt, six.string_types):
        return False

    return fmt in SUPPORTED_ATTESTATION_FORMATS


def _get_auth_data_rp_id_hash(auth_data):
    if not isinstance(auth_data, six.binary_type):
        return False

    auth_data_rp_id_hash = auth_data[:32]

    return auth_data_rp_id_hash


def _get_client_data_hash(decoded_client_data):
    if not isinstance(decoded_client_data, six.binary_type):
        return ''

    return hashlib.sha256(decoded_client_data).digest()


def _validate_credential_id(credential_id):
    if not isinstance(credential_id, six.string_types):
        return False

    return True


def _verify_signature(public_key, alg, data, signature):
    if alg == COSE_ALG_ES256:
        public_key.verify(signature, data, ECDSA(SHA256()))
    elif alg == COSE_ALG_RS256:
        public_key.verify(signature, data, PKCS1v15(), SHA256())
    elif alg == COSE_ALG_PS256:
        padding = PSS(mgf=MGF1(SHA256()), salt_length=32)
        public_key.verify(signature, data, padding, SHA256())
    else:
        raise NotImplementedError()
