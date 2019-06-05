import os
import unittest
import struct

from copy import copy

import webauthn

from webauthn import const

REGISTRATION_CHALLENGE = 'bPzpX3hHQtsp9evyKYkaZtVc9UN07PUdJ22vZUdDp94'
ASSERTION_CHALLENGE = 'e-g-nXaRxMagEiqTJSyD82RsEc5if_6jyfJDy8bNKlw'
RP_NAME = "Web Authentication"
RP_ID = "webauthn.io"
ORIGIN = "https://webauthn.io"
USER_ID = b'\x80\xf1\xdc\xec\xb5\x18\xb1\xc8b\x05\x886\xbc\xdfJ\xdf'
USER_NAME = "testuser"
USER_DISPLAY_NAME = "A Test User"
ICON_URL = "https://example.com/icon.png"

REGISTRATION_RESPONSE_TMPL = {
    'clientData': b'eyJ0eXBlIjogIndlYmF1dGhuLmNyZWF0ZSIsICJjbGllbnRFeHRlbnNpb25zIjoge30sICJjaGFsbGVuZ2UiOiAiYlB6cFgzaEhRdHNwOWV2eUtZa2FadFZjOVVOMDdQVWRKMjJ2WlVkRHA5NCIsICJvcmlnaW4iOiAiaHR0cHM6Ly93ZWJhdXRobi5pbyJ9',  # noqa
    'attObj': b'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEgwRgIhAI1qbvWibQos_t3zsTU05IXw1Ek3SDApATok09uc4UBwAiEAv0fB_lgb5Ot3zJ691Vje6iQLAtLhJDiA8zDxaGjcE3hjeDVjgVkCUzCCAk8wggE3oAMCAQICBDxoKU0wDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMDExLzAtBgNVBAMMJll1YmljbyBVMkYgRUUgU2VyaWFsIDIzOTI1NzM0ODExMTE3OTAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvd9nk9t3lMNQMXHtLE1FStlzZnUaSLql2fm1ajoggXlrTt8rzXuSehSTEPvEaEdv_FeSqX22L6Aoa8ajIAIOY6M7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAKrADVEJfuwVpIazebzEg0D4Z9OXLs5qZ_ukcONgxkRZ8K04QtP_CB5x6olTlxsj-SXArQDCRzEYUgbws6kZKfuRt2a1P-EzUiqDWLjRILSr-3_o7yR7ZP_GpiFKwdm-czb94POoGD-TS1IYdfXj94mAr5cKWx4EKjh210uovu_pLdLjc8xkQciUrXzZpPR9rT2k_q9HkZhHU-NaCJzky-PTyDbq0KKnzqVhWtfkSBCGw3ezZkTS-5lrvOKbIa24lfeTgu7FST5OwTPCFn8HcfWZMXMSD_KNU-iBqJdAwTLPPDRoLLvPTl29weCAIh-HUpmBQd0UltcPOrA_LFvAf61oYXV0aERhdGFYwnSm6pITyZwvdLIkkrMgz0AmKpTBqVCgOX8pJQtghB7wQQAAAAAAAAAAAAAAAAAAAAAAAAAAAECKU1ppjl9gmhHWyDkgHsUvZmhr6oF3_lD3llzLE2SaOSgOGIsIuAQqgp8JQSUu3r_oOaP8RS44dlQjrH-ALfYtpAECAyYhWCAxnqAfESXOYjKUc2WACuXZ3ch0JHxV0VFrrTyjyjIHXCJYIFnx8H87L4bApR4M-hPcV-fHehEOeW-KCyd0H-WGY8s6'  # noqa
}
ASSERTION_RESPONSE_TMPL = {
    'authData': b'dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvABAAACfQ',
    'clientData': b'eyJjaGFsbGVuZ2UiOiJlLWctblhhUnhNYWdFaXFUSlN5RDgyUnNFYzVpZl82anlmSkR5OGJOS2x3Iiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ',  # noqa
    'signature': b'304502204a76f05cd52a778cdd4df1565e0004e5cc1ead360419d0f5c3a0143bf37e7f15022100932b5c308a560cfe4f244214843075b904b3eda64e85d64662a81198c386cdde',  # noqa
}
ES256_KEY = {'alg': -7, 'type': 'public-key'}
HERE = os.path.abspath(os.path.dirname(__file__))
TRUST_ANCHOR_DIR = "{}/../webauthn/trusted_attestation_roots".format(HERE)


class WebAuthnTest(unittest.TestCase):
    def setUp(self):
        self.options = webauthn.WebAuthnMakeCredentialOptions(
            REGISTRATION_CHALLENGE,
            RP_NAME,
            RP_ID,
            USER_ID,
            USER_NAME,
            USER_DISPLAY_NAME,
            ICON_URL
        )

    def get_assertion_response(self):
        credential = self.test_validate_registration()
        webauthn_user = webauthn.WebAuthnUser(
            USER_ID,
            USER_NAME,
            USER_DISPLAY_NAME,
            ICON_URL,
            credential.credential_id.decode(),
            credential.public_key,
            credential.sign_count,
            credential.rp_id
        )

        webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
            webauthn_user,
            copy(ASSERTION_RESPONSE_TMPL),
            ASSERTION_CHALLENGE,
            ORIGIN,
            uv_required=False
        )

        return webauthn_assertion_response

    def test_create_options(self):
        registration_dict = self.options.registration_dict
        self.assertEqual(registration_dict['challenge'], REGISTRATION_CHALLENGE)
        self.assertTrue(ES256_KEY in registration_dict['pubKeyCredParams'])

    def test_validate_registration(self):
        registration_response = webauthn.WebAuthnRegistrationResponse(
            RP_ID,
            ORIGIN,
            copy(REGISTRATION_RESPONSE_TMPL),
            REGISTRATION_CHALLENGE,
            TRUST_ANCHOR_DIR,
            True,
            True,
            uv_required=False
        )

        return registration_response.verify()

    def test_registration_invalid_user_verification(self):
        registration_response = webauthn.WebAuthnRegistrationResponse(
            RP_ID,
            ORIGIN,
            copy(REGISTRATION_RESPONSE_TMPL),
            REGISTRATION_CHALLENGE,
            TRUST_ANCHOR_DIR,
            True,
            True,
            uv_required=True
        )

        with self.assertRaises(webauthn.webauthn.RegistrationRejectedException):
            registration_response.verify()

    def test_validate_assertion(self):
        webauthn_assertion_response = self.get_assertion_response()
        webauthn_assertion_response.verify()

    def test_invalid_signature_fail_assertion(self):
        def mess_up(response):
            response = copy(response)
            response['signature'] = b'00' + response['signature'][2:]
            return response

        webauthn_assertion_response = self.get_assertion_response()
        webauthn_assertion_response.assertion_response = mess_up(
            webauthn_assertion_response.assertion_response)

        with self.assertRaises(webauthn.webauthn.AuthenticationRejectedException):
            webauthn_assertion_response.verify()

    def test_no_user_presence_fail_assertion(self):
        webauthn_assertion_response = self.get_assertion_response()
        auth_data = webauthn.webauthn._webauthn_b64_decode(
            webauthn_assertion_response.assertion_response['authData'])
        flags = struct.unpack('!B', auth_data[32:33])[0]
        flags = flags & ~const.USER_PRESENT
        auth_data = auth_data[:32] + struct.pack('!B', flags) + auth_data[33:]
        webauthn_assertion_response.assertion_response[
            'authData'] = webauthn.webauthn._webauthn_b64_encode(auth_data)

        # TODO: This *should* fail because UP=0, but will fail anyway later on because
        # the signature is invalid. We should use a custom Authenticator implementation to
        # sign over an authenticator data statement with UP=0 and test against that so that
        # the signature is valid.
        with self.assertRaises(webauthn.webauthn.AuthenticationRejectedException):
            webauthn_assertion_response.verify()


if __name__ == '__main__':
    unittest.main()
