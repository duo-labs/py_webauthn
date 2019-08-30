import os
import unittest
import struct

from copy import copy

import webauthn

from webauthn import const


HERE = os.path.abspath(os.path.dirname(__file__))
TRUST_ANCHOR_DIR = "{}/../webauthn/trusted_attestation_roots".format(HERE)


class WebAuthnES256Test(unittest.TestCase):
    REGISTRATION_RESPONSE_TMPL = {
        'clientData': b'eyJ0eXBlIjogIndlYmF1dGhuLmNyZWF0ZSIsICJjbGllbnRFeHRlbnNpb25zIjoge30sICJjaGFsbGVuZ2UiOiAiYlB6cFgzaEhRdHNwOWV2eUtZa2FadFZjOVVOMDdQVWRKMjJ2WlVkRHA5NCIsICJvcmlnaW4iOiAiaHR0cHM6Ly93ZWJhdXRobi5pbyJ9',  # noqa
        'attObj': b'o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEgwRgIhAI1qbvWibQos_t3zsTU05IXw1Ek3SDApATok09uc4UBwAiEAv0fB_lgb5Ot3zJ691Vje6iQLAtLhJDiA8zDxaGjcE3hjeDVjgVkCUzCCAk8wggE3oAMCAQICBDxoKU0wDQYJKoZIhvcNAQELBQAwLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMDExLzAtBgNVBAMMJll1YmljbyBVMkYgRUUgU2VyaWFsIDIzOTI1NzM0ODExMTE3OTAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEvd9nk9t3lMNQMXHtLE1FStlzZnUaSLql2fm1ajoggXlrTt8rzXuSehSTEPvEaEdv_FeSqX22L6Aoa8ajIAIOY6M7MDkwIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjUwEwYLKwYBBAGC5RwCAQEEBAMCBSAwDQYJKoZIhvcNAQELBQADggEBAKrADVEJfuwVpIazebzEg0D4Z9OXLs5qZ_ukcONgxkRZ8K04QtP_CB5x6olTlxsj-SXArQDCRzEYUgbws6kZKfuRt2a1P-EzUiqDWLjRILSr-3_o7yR7ZP_GpiFKwdm-czb94POoGD-TS1IYdfXj94mAr5cKWx4EKjh210uovu_pLdLjc8xkQciUrXzZpPR9rT2k_q9HkZhHU-NaCJzky-PTyDbq0KKnzqVhWtfkSBCGw3ezZkTS-5lrvOKbIa24lfeTgu7FST5OwTPCFn8HcfWZMXMSD_KNU-iBqJdAwTLPPDRoLLvPTl29weCAIh-HUpmBQd0UltcPOrA_LFvAf61oYXV0aERhdGFYwnSm6pITyZwvdLIkkrMgz0AmKpTBqVCgOX8pJQtghB7wQQAAAAAAAAAAAAAAAAAAAAAAAAAAAECKU1ppjl9gmhHWyDkgHsUvZmhr6oF3_lD3llzLE2SaOSgOGIsIuAQqgp8JQSUu3r_oOaP8RS44dlQjrH-ALfYtpAECAyYhWCAxnqAfESXOYjKUc2WACuXZ3ch0JHxV0VFrrTyjyjIHXCJYIFnx8H87L4bApR4M-hPcV-fHehEOeW-KCyd0H-WGY8s6'  # noqa
    }
    ASSERTION_RESPONSE_TMPL = {
        'authData': b'dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvABAAACfQ',
        'clientData': b'eyJjaGFsbGVuZ2UiOiJlLWctblhhUnhNYWdFaXFUSlN5RDgyUnNFYzVpZl82anlmSkR5OGJOS2x3Iiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ',  # noqa
        'signature': b'304502204a76f05cd52a778cdd4df1565e0004e5cc1ead360419d0f5c3a0143bf37e7f15022100932b5c308a560cfe4f244214843075b904b3eda64e85d64662a81198c386cdde',  # noqa
    }
    CRED_KEY = {'alg': -7, 'type': 'public-key'}
    REGISTRATION_CHALLENGE = 'bPzpX3hHQtsp9evyKYkaZtVc9UN07PUdJ22vZUdDp94'
    ASSERTION_CHALLENGE = 'e-g-nXaRxMagEiqTJSyD82RsEc5if_6jyfJDy8bNKlw'
    RP_ID = "webauthn.io"
    ORIGIN = "https://webauthn.io"
    USER_NAME = 'testuser'
    ICON_URL = "https://example.com/icon.png"
    USER_DISPLAY_NAME = "A Test User"
    USER_ID = b'\x80\xf1\xdc\xec\xb5\x18\xb1\xc8b\x05\x886\xbc\xdfJ\xdf'
    RP_NAME = "Web Authentication"

    def setUp(self):
        self.options = webauthn.WebAuthnMakeCredentialOptions(
            self.REGISTRATION_CHALLENGE,
            self.RP_NAME,
            self.RP_ID,
            self.USER_ID,
            self.USER_NAME,
            self.USER_DISPLAY_NAME,
            self.ICON_URL
        )

    def get_assertion_response(self):
        credential = self.test_validate_registration()
        webauthn_user = webauthn.WebAuthnUser(
            self.USER_ID,
            self.USER_NAME,
            self.USER_DISPLAY_NAME,
            self.ICON_URL,
            credential.credential_id.decode(),
            credential.public_key,
            credential.sign_count,
            credential.rp_id
        )

        webauthn_assertion_response = webauthn.WebAuthnAssertionResponse(
            webauthn_user,
            copy(self.ASSERTION_RESPONSE_TMPL),
            self.ASSERTION_CHALLENGE,
            self.ORIGIN,
            uv_required=False,
        )

        return webauthn_assertion_response

    def test_create_options(self):
        registration_dict = self.options.registration_dict
        self.assertEqual(registration_dict['challenge'], self.REGISTRATION_CHALLENGE)
        self.assertTrue(self.CRED_KEY in registration_dict['pubKeyCredParams'])

    def test_validate_registration(self):
        registration_response = webauthn.WebAuthnRegistrationResponse(
            self.RP_ID,
            self.ORIGIN,
            copy(self.REGISTRATION_RESPONSE_TMPL),
            self.REGISTRATION_CHALLENGE,
            TRUST_ANCHOR_DIR,
            True,
            True,
            uv_required=False,
            none_attestation_permitted=True,
        )

        return registration_response.verify()

    def test_registration_invalid_user_verification(self):
        registration_response = webauthn.WebAuthnRegistrationResponse(
            self.RP_ID,
            self.ORIGIN,
            copy(self.REGISTRATION_RESPONSE_TMPL),
            self.REGISTRATION_CHALLENGE,
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


class WebAuthnRS256Test(WebAuthnES256Test):
    REGISTRATION_RESPONSE_TMPL = {
        'clientData': b'ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogIkJHN1RoNG40aU5VbU51UnFNakk4TlVoRmdjTlBXbXFQIiwNCgkib3JpZ2luIiA6ICJodHRwczovLzNmYWRmZDEzLm5ncm9rLmlvIiwNCgkidG9rZW5CaW5kaW5nIiA6IA0KCXsNCgkJInN0YXR1cyIgOiAic3VwcG9ydGVkIg0KCX0NCn0',  # noqa
        'attObj': b'o2NmbXRkbm9uZWhhdXRoRGF0YVkBZ8-CnWXgcASczJuZcxGxAUOJ7xA1fHeCSAxHxXqSqlMsRQAAAABgKLAXsdRMArSzr82vyWuyACCgTbLFqUdf_NegYeOYWcLCYBXlUddoptLz2eQO5DHa4qQBAwM5AQAgWQEAyo6eM5iARhHve7LwTvbhxT39qHviHjC1tzauY5BFnqAqYsj6m5Hl6NdyGQEDI-NLrm9kGKlxGLoDUZLoQlUVL0W2oltsLPYtgKLpAoEf6QfQx51j86NZiRClNERVKsQ-CtceQl_ic7zvK7HTMQQM_yWtaYjGo9t2IDPVgrkVnoSzuz_N-9ylCgjCm23-sllb6XhgvpXj44TDpiZFOhJDhYQksuqTjA1s08eXrPDwvc1Bcq5N8lJIc3eva07vecuZB53ywY0oZRWZ58aV035jjjPd-Kxp5JGi3H03ErvnHJCVxv64d-ngx7WvnqwsEvGVG3nauadeGzYWuGkgsxddeSFDAQABZ2F0dFN0bXSg'  # noqa
    }
    ASSERTION_RESPONSE_TMPL = {
        'authData': b'z4KdZeBwBJzMm5lzEbEBQ4nvEDV8d4JIDEfFepKqUywFAAAAAQ',
        'clientData': b'ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5nZXQiLA0KCSJjaGFsbGVuZ2UiIDogImJyS2xZNXFYTEx1bUdoYUdiSGxndlNUeUZJNEVIcnZQIiwNCgkib3JpZ2luIiA6ICJodHRwczovLzNmYWRmZDEzLm5ncm9rLmlvIiwNCgkidG9rZW5CaW5kaW5nIiA6IA0KCXsNCgkJInN0YXR1cyIgOiAic3VwcG9ydGVkIg0KCX0NCn0',  # noqa
        'signature': b'65d05b43495d4babc0388e6d530d7b0d676b0c29ddab4dce2445ebd053cc77ce43acc6d820c0d8491a0bae7beb98de8751d7497e07e061b7d26f4e490cd64b8bcd0628e1f50848d12b43f17493c9baf02bd4250a92c5d095d85faf7152a5132cd5f27c8223e61e683885021678a5156a955970d574926c52eec63b3bd25a205c4b51cb15c34c92ddd25b0ad370de96423e4b3edf5876963392f2ac889953f166669b96d16f894ef88e347484ab3cc81bc2814fbaf4b13dd1d483038bc4fb1354d564bc5aa944139ce6408e9078eddb6abef3a8ef4a77bcf74296ffd14c66223131d905f81cd149e1b8979c1bd87a036fca68f166e0644539b180d44f82fd7ed7',  # noqa
    }
    CRED_KEY = {'alg': -257, 'type': 'public-key'}
    REGISTRATION_CHALLENGE = 'BG7Th4n4iNUmNuRqMjI8NUhFgcNPWmqP'
    ASSERTION_CHALLENGE = 'brKlY5qXLLumGhaGbHlgvSTyFI4EHrvP'
    RP_NAME = "Web Authentication"
    RP_ID = "3fadfd13.ngrok.io"
    ORIGIN = "https://3fadfd13.ngrok.io"
    USER_NAME = "testuser"
    USER_DISPLAY_NAME = "A Test User"
    ICON_URL = "https://example.com/icon.png"
    USER_ID = b'\x80\xf1\xdc\xec\xb5\x18\xb1\xc8b\x05\x886\xbc\xdfJ\xdf'


if __name__ == '__main__':
    unittest.main()
