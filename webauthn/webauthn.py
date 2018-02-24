import base64
import hashlib
import json
import os
import six
import struct

import cbor2

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicNumbers)
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from OpenSSL import crypto


# Only supporting 'Basic' and 'Self Attestation' attestation types for now.
AT_BASIC = 'Basic'
AT_ECDAA = 'ECDAA'
AT_PRIVACY_CA = 'Privacy CA'
AT_SELF_ATTESTATION = 'Self Attestation'

SUPPORTED_ATTESTATION_TYPES = (
    AT_BASIC,
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
                'webauthn.location': True
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
                 none_attestation_permitted=False):
        self.rp_id = rp_id
        self.origin = origin
        self.registration_response = registration_response
        self.challenge = challenge
        self.trust_anchor_dir = trust_anchor_dir
        self.trusted_attestation_cert_required = trusted_attestation_cert_required

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

    def verify(self):
        try:
            # Step 1.
            #
            # Perform JSON deserialization on the clientDataJSON field
            # of the AuthenticatorAttestationResponse object to extract
            # the client data C claimed as collected during the credential
            # creation.
            credential_id = self.registration_response.get('id')
            raw_id = self.registration_response.get('rawId')
            attestation_object = self.registration_response.get('attObj')
            client_data = self.registration_response.get('clientData')
            credential_type = self.registration_response.get('type')
            decoded_cd = _webauthn_b64_decode(client_data)
            cd = json.loads(decoded_cd)

            # Step 2.
            #
            # Verify that the type in C is the string webauthn.create.
            received_type = cd.get('type')
            if not _verify_type(received_type, TYPE_CREATE):
                raise RegistrationRejectedException('Invalid type.')

            # Step 3.
            #
            # Verify that the challenge in C matches the challenge that
            # was sent to the authenticator in the create() call.
            received_challenge = cd.get('challenge')
            if not _verify_challenge(received_challenge, self.challenge):
                raise RegistrationRejectedException('Unable to verify challenge.')

            # Step 4.
            #
            # Verify that the origin in C matches the Relying Party's origin.
            if not _verify_origin(cd, self.origin):
                raise RegistrationRejectedException('Unable to verify origin.')

            # Step 5.
            #
            # Verify that the tokenBindingId in C matches the Token
            # Binding ID for the TLS connection over which the
            # attestation was obtained.
            if not _verify_token_binding_id(cd):
                raise RegistrationRejectedException('Unable to verify token binding ID.')

            # Step 6.
            #
            # Verify that the clientExtensions in C is a proper subset
            # of the extensions requested by the RP and that the
            # authenticatorExtensions in C is also a proper subset of
            # the extensions requested by the RP.
            if not _verify_client_extensions(cd):
                raise RegistrationRejectedException('Unable to verify client extensions.')
            if not _verify_authenticator_extensions(cd):
                raise RegistrationRejectedException('Unable to verify authenticator extensions.')

            # Step 7.
            #
            # Compute the hash of clientDataJSON using the algorithm
            # identified by C.hashAlgorithm.
            client_data_hash = _get_client_data_hash(cd, decoded_cd)

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
            # Determine the attestation statement format by performing
            # an USASCII case-sensitive match on fmt against the set of
            # supported WebAuthn Attestation Statement Format Identifier
            # values. The up-to-date list of registered WebAuthn
            # Attestation Statement Format Identifier values is maintained
            # in the in the IANA registry of the same name
            # [WebAuthn-Registries].
            if not _verify_attestation_statement_format(fmt):
                raise RegistrationRejectedException(
                    'Unable to verify attestation statement format.')

            # From authenticatorData, extract the claimed RP ID hash, the
            # claimed credential ID and the claimed credential public key.
            attestation_data = auth_data[37:]
            aaguid = attestation_data[:16]
            credential_id_len = struct.unpack('!H', attestation_data[16:18])[0]
            cred_id = attestation_data[18:18 + credential_id_len]
            b64_cred_id = _webauthn_b64_encode(cred_id)
            credential_pub_key = attestation_data[18 + credential_id_len:]

            # The [=credential public key=] encoded in COSE_Key format, as
            # defined in Section 7 of [[#RFC8152]], using the
            # [=CTAP canonical CBOR encoding form=].

            # The COSE_Key-encoded [=credential public key=] MUST contain the optional "alg"
            # parameter and MUST NOT contain any other optional parameters
            # The "alg" parameter MUST contain a {{COSEAlgorithmIdentifier}} value.

            # The encoded [=credential public key=] MUST also contain any additional
            # required parameters stipulated by the relevant key type specification,
            # i.e., required for the key type "kty" and algorithm "alg"
            # (see Section 8 of[[RFC8152]]).
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

            x = long(cpk[x_key].encode('hex'), 16)
            y = long(cpk[y_key].encode('hex'), 16)
            user_ec = EllipticCurvePublicNumbers(
                x, y,
                SECP256R1()).public_key(
                    backend=default_backend())
            encoded_user_pub_key = _encode_public_key(user_ec)

            # Verify public key length [65 bytes].
            if len(encoded_user_pub_key) != 65:
                raise RegistrationRejectedException('Bad public key.')

            if fmt == 'fido-u2f':
                # Step 11.
                #
                # Verify that attStmt is a correct, validly-signed attestation
                # statement, using the attestation statement format fmt's
                # verification procedure given authenticator data authData and
                # the hash of the serialized client data computed in step 6.

                # Verify that the given attestation statement is valid CBOR
                # conforming to the syntax defined above.
                if 'x5c' not in att_stmt or 'sig' not in att_stmt:
                    raise RegistrationRejectedException(
                        'Attestation statement must be a valid CBOR object.')
                # If x5c is not a certificate for an ECDSA public key over the
                # P-256 curve, stop verification and return an error.

                # Let authenticatorData denote the authenticator data claimed
                # to have been used for the attestation, and let clientDataHash
                # denote the hash of the serialized client data.

                # If clientDataHash is 256 bits long, set tbsHash to this value.
                # Otherwise set tbsHash to the SHA-256 hash of clientDataHash.
                if len(client_data_hash) == 32:
                    tbs_hash = client_data_hash
                else:
                    tbs_hash = hashlib.sha256(client_data_hash).digest()

                # Generate the claimed to-be-signed data as specified in
                # [FIDO-U2F-Message-Formats] section 4.3, with the application
                # parameter set to the claimed RP ID hash, the challenge
                # parameter set to tbsHash, the key handle parameter set to
                # the claimed credential ID of the given credential, and the
                # user public key parameter set to the claimed credential
                # public key.
                cert = att_stmt.get('x5c')[0]
                x509_attestation_cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)
                pem_public_key = crypto.dump_publickey(
                    crypto.FILETYPE_PEM, x509_attestation_cert.get_pubkey())
                signature = att_stmt['sig']
                bytes_to_sign = ''.join([
                    '\0',
                    auth_data_rp_id_hash,
                    tbs_hash,
                    cred_id,
                    encoded_user_pub_key])

                # Verify that the sig is a valid ECDSA P-256 signature over the
                # to-be-signed data constructed above.

                # The signature is to be verified by the relying party using the
                # public key certified in the attestation certificate. The relying
                # party should also verify that the attestation certificate was
                # issued by a trusted certification authority.
                pk = load_pem_public_key(pem_public_key, backend=default_backend())
                try:
                    pk.verify(signature, bytes_to_sign, ECDSA(SHA256()))
                except InvalidSignature:
                    raise RegistrationRejectedException('Invalid signature received.')

                # If successful, return attestation type Basic with the trust
                # path set to x5c.
                # Possible attestation types: Basic, Privacy CA,
                #                             Self Attestation, ECDAA
                attestation_type = AT_BASIC
                trust_path = x509_attestation_cert

                # Step 12.
                #
                # If validation is successful, obtain a list of acceptable trust
                # anchors (attestation root certificates or ECDAA-Issuer public
                # keys) for that attestation type and attestation statement format
                # fmt, from a trusted source or from policy. For example, the FIDO
                # Metadata Service [FIDOMetadataService] provides one way to obtain
                # such information, using the AAGUID in the attestation data
                # contained in authData.
                trust_anchors = _get_trust_anchors(attestation_type, fmt, self.trust_anchor_dir)
                if not trust_anchors and self.trusted_attestation_cert_required:
                    raise RegistrationRejectedException(
                        'No trust anchors available to verify attestation certificate.')

                # Step 13.
                #
                # Assess the attestation trustworthiness using the outputs of the
                # verification procedure in step 10, as follows:
                #
                #     * If self attestation was used, check if self attestation is
                #       acceptable under Relying Party policy.
                #     * If ECDAA was used, verify that the identifier of the
                #       ECDAA-Issuer public key used is included in the set of
                #       acceptable trust anchors obtained in step 11.
                #     * Otherwise, use the X.509 certificates returned by the
                #       verification procedure to verify that the attestation
                #       public key correctly chains up to an acceptable root
                #       certificate.
                if attestation_type == AT_SELF_ATTESTATION:
                    if not self.self_attestation_permitted:
                        raise RegistrationRejectedException('Self attestation is not permitted.')
                elif attestation_type == AT_PRIVACY_CA:
                    raise NotImplementedError(
                        'Privacy CA attestation type is not currently supported.')
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

                # Step 14.
                #
                # If the attestation statement attStmt verified successfully and is
                # found to be trustworthy, then register the new credential with the
                # account that was denoted in the options.user passed to create(),
                # by associating it with the credential ID and credential public key
                # contained in authData's attestation data, as appropriate for the
                # Relying Party's systems.

                # Step 15.
                #
                # If the attestation statement attStmt successfully verified but is
                # not trustworthy per step 12 above, the Relying Party SHOULD fail
                # the registration ceremony.
                #
                #     NOTE: However, if permitted by policy, the Relying Party MAY
                #           register the credential ID and credential public key but
                #           treat the credential as one with self attestation (see
                #           5.3.3 Attestation Types). If doing so, the Relying Party
                #           is asserting there is no cryptographic proof that the
                #           public key credential has been generated by a particular
                #           authenticator model. See [FIDOSecRef] and [UAFProtocol]
                #           for a more detailed discussion.
            elif fmt == 'none':
                # `none` - indicates that the Relying Party is not interested in
                # authenticator attestation.
                if not self.none_attestation_permitted:
                    raise RegistrationRejectedException('Authenticator attestation is required.')
            else:
                raise RegistrationRejectedException('Invalid format.')

            sc = auth_data[33:37]
            sign_count = struct.unpack('!I', sc)[0]

            credential = WebAuthnCredential(
                self.rp_id,
                self.origin,
                b64_cred_id,
                base64.b64encode(encoded_user_pub_key),
                sign_count)

            return credential

        except Exception as e:
            raise RegistrationRejectedException(
                'Registration rejected. Error: {}.'.format(e))


class WebAuthnAssertionResponse(object):

    def __init__(self, webauthn_user, assertion_response, challenge, origin, uv_required=False):
        self.webauthn_user = webauthn_user
        self.assertion_response = assertion_response
        self.challenge = challenge
        self.origin = origin
        self.uv_required = uv_required

    def verify(self):
        try:
            # Step 1.
            #
            # Using credential's id attribute (or the corresponding rawId, if
            # base64url encoding is inappropriate for your use case), look up
            # the corresponding credential public key.
            if not _validate_credential_id(self.webauthn_user.credential_id):
                raise AuthenticationRejectedException('Invalid credential ID.')

            if not isinstance(self.webauthn_user, WebAuthnUser):
                raise AuthenticationRejectedException('Invalid user type.')

            # Step 2.
            # Let cData, aData and sig denote the value of credential's
            # response's clientDataJSON, authenticatorData, and signature
            # respectively.
            c_data = self.assertion_response.get('clientData')
            a_data = self.assertion_response.get('authData')
            decoded_a_data = _webauthn_b64_decode(a_data)
            sig = self.assertion_response.get('signature').decode('hex')

            # Step 3.
            # Perform JSON deserialization on cData to extract the client
            # data C used for the signature.
            decoded_cd = _webauthn_b64_decode(c_data)
            cd = json.loads(decoded_cd)

            # Step 4.
            # Verify that the type in C is the string webauthn.get.
            received_type = cd.get('type')
            if not _verify_type(received_type, TYPE_GET):
                raise RegistrationRejectedException('Invalid type.')

            # Step 5.
            # Verify that the challenge member of C matches the challenge
            # that was sent to the authenticator in the
            # PublicKeyCredentialRequestOptions passed to the get() call.
            received_challenge = cd.get('challenge')
            if not _verify_challenge(received_challenge, self.challenge):
                raise AuthenticationRejectedException('Unable to verify challenge.')

            # Step 6.
            # Verify that the origin member of C matches the Relying
            # Party's origin.
            if not _verify_origin(cd, self.origin):
                raise AuthenticationRejectedException('Unable to verify origin.')

            # Step 7.
            # Verify that the tokenBindingId member of C (if present)
            # matches the Token Binding ID for the TLS connection over
            # which the signature was obtained.
            if not _verify_token_binding_id(cd):
                raise AuthenticationRejectedException('Unable to verify token binding ID.')

            # Step 8.
            # Verify that the clientExtensions member of C is a proper
            # subset of the extensions requested by the Relying Party
            # and that the authenticatorExtensions in C is also a proper
            # subset of the extensions requested by the Relying Party.
            if not _verify_client_extensions(cd):
                raise AuthenticationRejectedException('Unable to verify client extensions.')
            if not _verify_authenticator_extensions(cd):
                raise AuthenticationRejectedException('Unable to verify authenticator extensions.')

            # Step 9.
            # Verify that the RP ID hash in aData is the SHA-256 hash of
            # the RP ID expected by the Relying Party.
            auth_data_rp_id_hash = _get_auth_data_rp_id_hash(decoded_a_data)
            if not _verify_rp_id_hash(auth_data_rp_id_hash, self.webauthn_user.rp_id):
                raise AuthenticationRejectedException('Unable to verify RP ID hash.')

            # Step 10.
            # Let hash be the result of computing a hash over the cData
            # using the algorithm represented by the hashAlgorithm member
            # of C.
            client_data_hash = _get_client_data_hash(cd, decoded_cd)

            # Step 11.
            # Using the credential public key looked up in step 1, verify
            # that sig is a valid signature over the binary concatenation
            # of aData and hash.
            decoded_user_pub_key = _decode_public_key(
                base64.b64decode(self.webauthn_user.public_key))
            user_pubkey = decoded_user_pub_key.public_key(backend=default_backend())
            bytes_to_sign = ''.join([
                decoded_a_data,
                client_data_hash])
            try:
                user_pubkey.verify(sig, bytes_to_sign, ECDSA(SHA256()))
            except InvalidSignature:
                raise AuthenticationRejectedException('Invalid signature received.')

            sc = decoded_a_data[33:37]
            sign_count = struct.unpack('!I', sc)[0]
            if sign_count <= self.webauthn_user.sign_count:
                raise AuthenticationRejectedException('Duplicate authentication detected.')

            # Authenticator data flags.
            # https://www.w3.org/TR/webauthn/#authenticator-data
            flags = struct.unpack('!B', decoded_a_data[32])[0]
            user_present = 1 << 0
            user_verified = 1 << 2
            attestation_data_included = 1 << 6
            extension_data_included = 1 << 7
            if (flags & user_present) != 0x01:
                raise AuthenticationRejectedException('Malformed request received.')
            if (self.uv_required and (flags & user_verified) != 0x01):
                raise AuthenticationRejectedException('Malformed request received.')

            # Step 12.
            # If the signature counter value adata.signCount is nonzero
            # or the value stored in conjunction with credential's id
            # attribute is nonzero, then run the following substep:
            #     If the signature counter value adata.signCount is:
            #         greater than the signature counter value stored in
            #         conjunction with credential's id attribute:
            #             Update the stored signature counter value,
            #             associated with credential's id attribute,
            #             to be the value of adata.signCount.
            #         less than or equal to the signature counter value
            #         stored in conjunction with credential's id attribute:
            #             This is an signal that the authenticator may be
            #             cloned, i.e. at least two copies of the credential
            #             private key may exist and are being used in parallel.
            #             Relying Parties should incorporate this information
            #             into their risk scoring. Whether the Relying Party
            #             updates the stored signature counter value in this
            #             case, or not, or fails the authentication ceremony
            #             or not, is Relying Party-specific.

            # Step 13.
            # If all the above steps are successful, continue with the
            # authentication ceremony as appropriate. Otherwise, fail the
            # authentication ceremony.

            return sign_count

        except Exception as e:
            raise AuthenticationRejectedException(
                'Authentication rejected. Error: {}.'.format(e))


def _encode_public_key(public_key):
    '''Extracts the x,y coordinates from a public point on a Cryptography elliptic
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
    store = crypto.X509Store()
    for _ta in trust_anchors:
        store.add_cert(_ta)
    store_ctx = crypto.X509StoreContext(store, trust_path)

    try:
        store_ctx.verify_certificate()
        return True
    except Exception as e:
        print('Unable to verify certificate: {}.'.format(e))

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
    # Optional
    # https://www.w3.org/TR/webauthn/#dom-collectedclientdata-tokenbindingid
    return True


def _verify_client_extensions(client_data):
    # Optional
    # https://www.w3.org/TR/webauthn/#dom-collectedclientdata-clientextensions
    return True


def _verify_authenticator_extensions(client_data):
    # Optional
    # https://www.w3.org/TR/webauthn/#dom-collectedclientdata-authenticatorextensions
    return True


def _verify_rp_id_hash(auth_data_rp_id_hash, rp_id):
    rp_id_hash = hashlib.sha256(rp_id).digest()

    return auth_data_rp_id_hash == rp_id_hash


def _verify_attestation_statement_format(fmt):
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


def _get_client_data_hash(client_data, decoded_client_data):
    if not isinstance(client_data, dict):
        return ''
    if not isinstance(decoded_client_data, six.string_types):
        return ''

    hash_alg = client_data.get('hashAlgorithm')

    if not hash_alg:
        return ''
    if hash_alg == 'SHA-256':
        return hashlib.sha256(decoded_client_data).digest()
    elif hash_alg == 'SHA-512':
        return hashlib.sha512(decoded_client_data).digest()

    return ''


def _validate_credential_id(credential_id):
    if not isinstance(credential_id, six.string_types):
        return False

    return True
