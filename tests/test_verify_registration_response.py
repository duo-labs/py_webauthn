import json
from unittest import TestCase
from unittest.mock import MagicMock, patch

from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    encode_cbor,
    parse_registration_credential_json,
    parse_cbor,
    parse_attestation_object,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.exceptions import InvalidRegistrationResponse, InvalidCBORData
from webauthn.helpers.known_root_certs import globalsign_r2
from webauthn.helpers.structs import (
    AttestationFormat,
    PublicKeyCredentialType,
)
from webauthn import verify_registration_response


class TestVerifyRegistrationResponse(TestCase):
    def test_verifies_none_attestation_response(self) -> None:
        credential = """{
            "id": "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w",
            "rawId": "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w",
            "response": {
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAFwAAAAAAAAAAAAAAAAAAAAAAQPctcQPE5oNRRJk_nO_371mf7qE7qIodzr0eOf6ACvnMB1oQG165dqutoi1U44shGezu5_gkTjmOPeJO0N8a7P-lAQIDJiABIVggSFbUJF-42Ug3pdM8rDRFu_N5oiVEysPDB6n66r_7dZAiWCDUVnB39FlGypL-qAoIO9xWHtJygo2jfDmHl-_eKFRLDA",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVHdON240V1R5R0tMYzRaWS1xR3NGcUtuSE00bmdscXN5VjBJQ0psTjJUTzlYaVJ5RnRya2FEd1V2c3FsLWdrTEpYUDZmbkYxTWxyWjUzTW00UjdDdnciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
            },
            "type": "public-key",
            "clientExtensionResults": {},
            "transports": [
                "nfc",
                "usb"
            ]
        }"""

        challenge = base64url_to_bytes(
            "TwN7n4WTyGKLc4ZY-qGsFqKnHM4nglqsyV0ICJlN2TO9XiRyFtrkaDwUvsql-gkLJXP6fnF1MlrZ53Mm4R7Cvw"
        )
        rp_id = "localhost"
        expected_origin = "http://localhost:5000"

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=expected_origin,
            expected_rp_id=rp_id,
        )

        assert verification.fmt == AttestationFormat.NONE
        assert verification.aaguid == "00000000-0000-0000-0000-000000000000"
        assert verification.credential_id == base64url_to_bytes(
            "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w"
        )
        assert verification.credential_public_key == base64url_to_bytes(
            "pQECAyYgASFYIEhW1CRfuNlIN6XTPKw0RbvzeaIlRMrDwwep-uq_-3WQIlgg1FZwd_RZRsqS_qgKCDvcVh7ScoKNo3w5h5fv3ihUSww"
        )
        assert verification.attestation_object == base64url_to_bytes(
            "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAFwAAAAAAAAAAAAAAAAAAAAAAQPctcQPE5oNRRJk_nO_371mf7qE7qIodzr0eOf6ACvnMB1oQG165dqutoi1U44shGezu5_gkTjmOPeJO0N8a7P-lAQIDJiABIVggSFbUJF-42Ug3pdM8rDRFu_N5oiVEysPDB6n66r_7dZAiWCDUVnB39FlGypL-qAoIO9xWHtJygo2jfDmHl-_eKFRLDA"
        )
        assert verification.credential_type == PublicKeyCredentialType.PUBLIC_KEY
        assert verification.sign_count == 23
        assert verification.credential_backed_up is False
        assert verification.credential_device_type == "single_device"

    @patch("webauthn.registration.verify_registration_response.parse_attestation_object")
    def test_verifies_response_optional_user_presence(
        self,
        mock_parse_attestation_object: MagicMock,
    ) -> None:

        credential = parse_registration_credential_json(
            {
                "id": "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w",
                "rawId": "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w",
                "response": {
                    "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAFwAAAAAAAAAAAAAAAAAAAAAAQPctcQPE5oNRRJk_nO_371mf7qE7qIodzr0eOf6ACvnMB1oQG165dqutoi1U44shGezu5_gkTjmOPeJO0N8a7P-lAQIDJiABIVggSFbUJF-42Ug3pdM8rDRFu_N5oiVEysPDB6n66r_7dZAiWCDUVnB39FlGypL-qAoIO9xWHtJygo2jfDmHl-_eKFRLDA",
                    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVHdON240V1R5R0tMYzRaWS1xR3NGcUtuSE00bmdscXN5VjBJQ0psTjJUTzlYaVJ5RnRya2FEd1V2c3FsLWdrTEpYUDZmbkYxTWxyWjUzTW00UjdDdnciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                },
                "type": "public-key",
                "clientExtensionResults": {},
                "transports": ["nfc", "usb"],
            }
        )

        # Grab the actual authenticator data out of the credential above
        attestation_object = parse_attestation_object(credential.response.attestation_object)
        # Pretend this is a conditional create response
        attestation_object.auth_data.flags.up = False
        attestation_object.auth_data.flags.uv = False

        mock_parse_attestation_object.return_value = attestation_object

        challenge = base64url_to_bytes(
            "TwN7n4WTyGKLc4ZY-qGsFqKnHM4nglqsyV0ICJlN2TO9XiRyFtrkaDwUvsql-gkLJXP6fnF1MlrZ53Mm4R7Cvw"
        )
        rp_id = "localhost"
        expected_origin = "http://localhost:5000"

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=expected_origin,
            expected_rp_id=rp_id,
            # Be okay with up:False
            require_user_presence=False,
            require_user_verification=False,
        )

        assert verification.fmt == AttestationFormat.NONE

    def test_raises_exception_on_unsupported_attestation_type(self) -> None:
        cred_json = {
            "id": "FsWBrFcw8yRjxV8z18Egh91o1AScNRYkIuUoY6wIlIhslDpP7eydKi1q5s9g1ugDP9mqBlPDDFPRbH6YLwHbtg",
            "rawId": "FsWBrFcw8yRjxV8z18Egh91o1AScNRYkIuUoY6wIlIhslDpP7eydKi1q5s9g1ugDP9mqBlPDDFPRbH6YLwHbtg",
            "response": {
                "attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIgRpuZ6hdaLAgWgCFTIo4BGSTBAxwwqk4u3s1-JAzv_H4CIQCZnfoic34aOwlac1A09eflEtb0V1kO7yGhHOw5P5wVWmN4NWOBWQLBMIICvTCCAaWgAwIBAgIEKudiYzANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNzE5ODA3MDc1MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKgOGXmBD2Z4R_xCqJVRXhL8Jr45rHjsyFykhb1USGozZENOZ3cdovf5Ke8fj2rxi5tJGn_VnW4_6iQzKdIaeP6NsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQbUS6m_bsLkm5MAyP6SDLczAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQByV9A83MPhFWmEkNb4DvlbUwcjc9nmRzJjKxHc3HeK7GvVkm0H4XucVDB4jeMvTke0WHb_jFUiApvpOHh5VyMx5ydwFoKKcRs5x0_WwSWL0eTZ5WbVcHkDR9pSNcA_D_5AsUKOBcbpF5nkdVRxaQHuuIuwV4k1iK2IqtMNcU8vL6w21U261xCcWwJ6sMq4zzVO8QCKCQhsoIaWrwz828GDmPzfAjFsJiLJXuYivdHACkeJ5KHMt0mjVLpfJ2BCML7_rgbmvwL7wBW80VHfNdcKmKjkLcpEiPzwcQQhiN_qHV90t-p4iyr5xRSpurlP5zic2hlRkLKxMH2_kRjhqSn4aGF1dGhEYXRhWMRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0UAAAAqbUS6m_bsLkm5MAyP6SDLcwBAFsWBrFcw8yRjxV8z18Egh91o1AScNRYkIuUoY6wIlIhslDpP7eydKi1q5s9g1ugDP9mqBlPDDFPRbH6YLwHbtqUBAgMmIAEhWCAq3y0RWh8nLzanBZQwTA7yAbUy9KEDAM0b3N9Elrb0VCJYIJrX7ygtpyInb5mXBE7g9YEow6xWrJ400HhL2r4q5tzV",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoicERSbWtkZHVBaS1BVTJ4Nm8tRnFxaEkzWEsybmxWbHNDU3IwNHpXa050djg0SndyTUh0RWxSSEhVV0xFRGhrckVhUThCMWxCY0lIX1ZTUnFwX1JBQXciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
            },
            "type": "public-key",
            "clientExtensionResults": {},
            "transports": ["nfc", "usb"],
        }

        # Take the otherwise legitimate credential and mangle its attestationObject's
        # "fmt" to something it could never actually be
        parsed_atte_obj: dict = parse_cbor(
            base64url_to_bytes(cred_json["response"]["attestationObject"])  # type: ignore
        )
        parsed_atte_obj["fmt"] = "not_real_fmt"
        cred_json["response"]["attestationObject"] = bytes_to_base64url(  # type: ignore
            encode_cbor(parsed_atte_obj)
        )

        credential = json.dumps(cred_json)
        challenge = base64url_to_bytes(
            "pDRmkdduAi-AU2x6o-FqqhI3XK2nlVlsCSr04zWkNtv84JwrMHtElRHHUWLEDhkrEaQ8B1lBcIH_VSRqp_RAAw"
        )
        rp_id = "localhost"
        expected_origin = "http://localhost:5000"

        with self.assertRaises(InvalidRegistrationResponse):
            verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_origin=expected_origin,
                expected_rp_id=rp_id,
            )

    def test_supports_multiple_expected_origins(self) -> None:
        credential = """{
            "id": "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w",
            "rawId": "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w",
            "response": {
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAFwAAAAAAAAAAAAAAAAAAAAAAQPctcQPE5oNRRJk_nO_371mf7qE7qIodzr0eOf6ACvnMB1oQG165dqutoi1U44shGezu5_gkTjmOPeJO0N8a7P-lAQIDJiABIVggSFbUJF-42Ug3pdM8rDRFu_N5oiVEysPDB6n66r_7dZAiWCDUVnB39FlGypL-qAoIO9xWHtJygo2jfDmHl-_eKFRLDA",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVHdON240V1R5R0tMYzRaWS1xR3NGcUtuSE00bmdscXN5VjBJQ0psTjJUTzlYaVJ5RnRya2FEd1V2c3FsLWdrTEpYUDZmbkYxTWxyWjUzTW00UjdDdnciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
            },
            "type": "public-key",
            "clientExtensionResults": {},
            "transports": [
                "nfc",
                "usb"
            ]
        }"""

        challenge = base64url_to_bytes(
            "TwN7n4WTyGKLc4ZY-qGsFqKnHM4nglqsyV0ICJlN2TO9XiRyFtrkaDwUvsql-gkLJXP6fnF1MlrZ53Mm4R7Cvw"
        )
        rp_id = "localhost"
        expected_origin = ["https://foo.bar", "http://localhost:5000"]

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=expected_origin,
            expected_rp_id=rp_id,
        )

        assert verification.credential_id == base64url_to_bytes(
            "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w"
        )

    def test_raises_when_root_cert_invalid_for_response(self) -> None:
        # "packed"
        credential = """{
            "id": "syGQPDZRUYdb4m3rdWeyPaIMYlbmydGp1TP_33vE_lqJ3PHNyTd0iKsnKr5WjnCcBzcesZrDEfB_RBLFzU3k4w",
            "rawId": "syGQPDZRUYdb4m3rdWeyPaIMYlbmydGp1TP_33vE_lqJ3PHNyTd0iKsnKr5WjnCcBzcesZrDEfB_RBLFzU3k4w",
            "response": {
                "attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEcwRQIhAOfrFlQpbavT6dJeTDJSCDzYSYPjBDHli2-syT2c1IiKAiAx5gQ2z5cHjdQX-jEHTb7JcjfQoVSW8fXszF5ihSgeOGN4NWOBWQLBMIICvTCCAaWgAwIBAgIEKudiYzANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbjELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEnMCUGA1UEAwweWXViaWNvIFUyRiBFRSBTZXJpYWwgNzE5ODA3MDc1MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKgOGXmBD2Z4R_xCqJVRXhL8Jr45rHjsyFykhb1USGozZENOZ3cdovf5Ke8fj2rxi5tJGn_VnW4_6iQzKdIaeP6NsMGowIgYJKwYBBAGCxAoCBBUxLjMuNi4xLjQuMS40MTQ4Mi4xLjEwEwYLKwYBBAGC5RwCAQEEBAMCBDAwIQYLKwYBBAGC5RwBAQQEEgQQbUS6m_bsLkm5MAyP6SDLczAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQByV9A83MPhFWmEkNb4DvlbUwcjc9nmRzJjKxHc3HeK7GvVkm0H4XucVDB4jeMvTke0WHb_jFUiApvpOHh5VyMx5ydwFoKKcRs5x0_WwSWL0eTZ5WbVcHkDR9pSNcA_D_5AsUKOBcbpF5nkdVRxaQHuuIuwV4k1iK2IqtMNcU8vL6w21U261xCcWwJ6sMq4zzVO8QCKCQhsoIaWrwz828GDmPzfAjFsJiLJXuYivdHACkeJ5KHMt0mjVLpfJ2BCML7_rgbmvwL7wBW80VHfNdcKmKjkLcpEiPzwcQQhiN_qHV90t-p4iyr5xRSpurlP5zic2hlRkLKxMH2_kRjhqSn4aGF1dGhEYXRhWMRJlg3liA6MaHQ0Fw9kdmBbj-SuuaKGMseZXPO6gx2XY0UAAAA0bUS6m_bsLkm5MAyP6SDLcwBAsyGQPDZRUYdb4m3rdWeyPaIMYlbmydGp1TP_33vE_lqJ3PHNyTd0iKsnKr5WjnCcBzcesZrDEfB_RBLFzU3k46UBAgMmIAEhWCBAX_i3O3DvBnkGq_uLNk_PeAX5WwO_MIxBp0mhX6Lw7yJYIOW-1-Fch829McWvRUYAHTWZTx5IycKSGECL1UzUaK_8",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiOExCQ2lPWTNxMWNCWkhGQVd0UzRBWlpDaHpHcGh5NjdsSzdJNzB6S2k0eUM3cGdyUTJQY2g3bkFqTGsxd3E5Z3Jlc2hJQXNXMkFqaWJoWGpqSTBUbVEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
            },
            "type": "public-key",
            "clientExtensionResults": {},
            "transports": [
                "nfc",
                "usb"
            ]
        }"""
        challenge = base64url_to_bytes(
            "8LBCiOY3q1cBZHFAWtS4AZZChzGphy67lK7I70zKi4yC7pgrQ2Pch7nAjLk1wq9greshIAsW2AjibhXjjI0TmQ"
        )
        rp_id = "localhost"
        expected_origin = "http://localhost:5000"

        with self.assertRaises(InvalidRegistrationResponse):
            verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_origin=expected_origin,
                expected_rp_id=rp_id,
                pem_root_certs_bytes_by_fmt={
                    # This root cert is actually for android-safetynet
                    AttestationFormat.PACKED: [globalsign_r2]
                },
            )

    def test_verifies_registration_over_cable(self) -> None:
        credential = """{
            "id": "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w",
            "rawId": "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w",
            "response": {
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAFwAAAAAAAAAAAAAAAAAAAAAAQPctcQPE5oNRRJk_nO_371mf7qE7qIodzr0eOf6ACvnMB1oQG165dqutoi1U44shGezu5_gkTjmOPeJO0N8a7P-lAQIDJiABIVggSFbUJF-42Ug3pdM8rDRFu_N5oiVEysPDB6n66r_7dZAiWCDUVnB39FlGypL-qAoIO9xWHtJygo2jfDmHl-_eKFRLDA",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVHdON240V1R5R0tMYzRaWS1xR3NGcUtuSE00bmdscXN5VjBJQ0psTjJUTzlYaVJ5RnRya2FEd1V2c3FsLWdrTEpYUDZmbkYxTWxyWjUzTW00UjdDdnciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
            },
            "type": "public-key",
            "clientExtensionResults": {},
            "transports": [
                "cable"
            ]
        }"""

        challenge = base64url_to_bytes(
            "TwN7n4WTyGKLc4ZY-qGsFqKnHM4nglqsyV0ICJlN2TO9XiRyFtrkaDwUvsql-gkLJXP6fnF1MlrZ53Mm4R7Cvw"
        )
        rp_id = "localhost"
        expected_origin = "http://localhost:5000"

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=expected_origin,
            expected_rp_id=rp_id,
        )

        assert verification.fmt == AttestationFormat.NONE

    def test_supports_already_parsed_credential(self) -> None:
        parsed_credential = parse_registration_credential_json(
            """{
                "id": "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w",
                "rawId": "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w",
                "response": {
                    "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAFwAAAAAAAAAAAAAAAAAAAAAAQPctcQPE5oNRRJk_nO_371mf7qE7qIodzr0eOf6ACvnMB1oQG165dqutoi1U44shGezu5_gkTjmOPeJO0N8a7P-lAQIDJiABIVggSFbUJF-42Ug3pdM8rDRFu_N5oiVEysPDB6n66r_7dZAiWCDUVnB39FlGypL-qAoIO9xWHtJygo2jfDmHl-_eKFRLDA",
                    "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVHdON240V1R5R0tMYzRaWS1xR3NGcUtuSE00bmdscXN5VjBJQ0psTjJUTzlYaVJ5RnRya2FEd1V2c3FsLWdrTEpYUDZmbkYxTWxyWjUzTW00UjdDdnciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
                },
                "type": "public-key",
                "clientExtensionResults": {},
                "transports": [
                    "cable"
                ]
            }"""
        )

        challenge = base64url_to_bytes(
            "TwN7n4WTyGKLc4ZY-qGsFqKnHM4nglqsyV0ICJlN2TO9XiRyFtrkaDwUvsql-gkLJXP6fnF1MlrZ53Mm4R7Cvw"
        )
        rp_id = "localhost"
        expected_origin = "http://localhost:5000"

        verification = verify_registration_response(
            credential=parsed_credential,
            expected_challenge=challenge,
            expected_origin=expected_origin,
            expected_rp_id=rp_id,
        )

        assert verification.fmt == AttestationFormat.NONE

    def test_supports_dict_credential(self) -> None:
        credential = {
            "id": "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w",
            "rawId": "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w",
            "response": {
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAFwAAAAAAAAAAAAAAAAAAAAAAQPctcQPE5oNRRJk_nO_371mf7qE7qIodzr0eOf6ACvnMB1oQG165dqutoi1U44shGezu5_gkTjmOPeJO0N8a7P-lAQIDJiABIVggSFbUJF-42Ug3pdM8rDRFu_N5oiVEysPDB6n66r_7dZAiWCDUVnB39FlGypL-qAoIO9xWHtJygo2jfDmHl-_eKFRLDA",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVHdON240V1R5R0tMYzRaWS1xR3NGcUtuSE00bmdscXN5VjBJQ0psTjJUTzlYaVJ5RnRya2FEd1V2c3FsLWdrTEpYUDZmbkYxTWxyWjUzTW00UjdDdnciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
            },
            "type": "public-key",
            "clientExtensionResults": {},
            "transports": ["cable"],
        }

        challenge = base64url_to_bytes(
            "TwN7n4WTyGKLc4ZY-qGsFqKnHM4nglqsyV0ICJlN2TO9XiRyFtrkaDwUvsql-gkLJXP6fnF1MlrZ53Mm4R7Cvw"
        )
        rp_id = "localhost"
        expected_origin = "http://localhost:5000"

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=expected_origin,
            expected_rp_id=rp_id,
        )

        assert verification.fmt == AttestationFormat.NONE

    def test_raises_useful_error_on_bad_attestation_object(self) -> None:
        credential = {
            "id": "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w",
            "rawId": "9y1xA8Tmg1FEmT-c7_fvWZ_uoTuoih3OvR45_oAK-cwHWhAbXrl2q62iLVTjiyEZ7O7n-CROOY494k7Q3xrs_w",
            "response": {
                "attestationObject": "",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiVHdON240V1R5R0tMYzRaWS1xR3NGcUtuSE00bmdscXN5VjBJQ0psTjJUTzlYaVJ5RnRya2FEd1V2c3FsLWdrTEpYUDZmbkYxTWxyWjUzTW00UjdDdnciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
            },
            "type": "public-key",
            "clientExtensionResults": {},
            "transports": ["cable"],
        }

        challenge = base64url_to_bytes(
            "TwN7n4WTyGKLc4ZY-qGsFqKnHM4nglqsyV0ICJlN2TO9XiRyFtrkaDwUvsql-gkLJXP6fnF1MlrZ53Mm4R7Cvw"
        )
        rp_id = "localhost"
        expected_origin = "http://localhost:5000"

        with self.assertRaises(InvalidCBORData):
            verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_origin=expected_origin,
                expected_rp_id=rp_id,
            )

    def test_verify_pqc_ml_dsa_44_packed_response(self) -> None:
        credential = {
            "id": "-EM9FDFIdFVeqWdTycRjoZVN2ZS4vnVE-MBpg7k0pl4jpuqj4GnMCW3Wqlm2WWI2PQ",
            "rawId": "-EM9FDFIdFVeqWdTycRjoZVN2ZS4vnVE-MBpg7k0pl4jpuqj4GnMCW3Wqlm2WWI2PQ",
            "response": {
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkFoHSm6pITyZwvdLIkkrMgz0AmKpTBqVCgOX8pJQtghB7wxQAAAAQAAAAAAAAAAAAAAAAAAAAAADH4Qz0UMUh0VV6pZ1PJxGOhlU3ZlLi-dUT4wGmDuTSmXiOm6qPgacwJbdaqWbZZYjY9owEHAzgvIFkFIC4AIUrgARve17AEk0W30POluaL08p91eLXkktSjmAlmZdNTWhtUFj3wkseZEt4xpmWarG28Za86i7yq-B4df3uOuq3zQVTKOQUWJLWGJ3-wUUuyywPtkdgSqzQdcli6xMgwnVqh9r6FVL9Xp7x3kgjUVDqhux_k1D2d4ts2zqi1rUrSF6FNX139g3dd1VnUNQrMLdrwohR9CmE0fZ6Am4Df_OV2JxOrUEPzMFi5SeBcrU1oSj2lX_91gY179PO0wIOtTa1KzWvwOYa_KjOj9Ow16AtmsXrcpL-jYW4_bFn4kpT9G-vDG4qPFDpint62g0DDjEt7JrF288aIZXOpsbVmnjw2_O_5pFFvFpH32gD7_NdmvE6PSymNxPcTCnMzY3xv5wJXiEDhO21E85n78Oay4k7PzWHvzQxlJldIYw-9TfKZXqZa6sIbE-LyZj_Y2FV1Owd4WLvKCNcO-IIP3XFcZ7__XPZtAsBTJ5Z5w18jRnlMNKTygva-F2Ec65tA2skED9PnVyS_WjtZN5VjbhuU-D9DIDXEgUjitdcXWbCruDjxaBwjuDFXOI9cYdp4n-KWCZGJdX9QFHDGkvX6zDXupFrFV1q1JeKCayuMJjL3Z44AMF2UtjNODzhlviE8neX5NSfXdf36FWGFER6D6YCGGvooW8EBCx8OLPRNGGwoKBrEflr_ISYIdyw8-rDkAG0-bka_ulzfg8uTY8BXNu0HhqsteUPni4HlhUXMb0yI1DbLi5hTTkpBEBfmjzTJ8JMDe9sOOaqU2PrOzvIs5c7fx_VBqQZbF6amei2Y41okZJWwW0LWNvL2JQ_Yj9deHMczichCHWVX3uCL-SfPL3AaLeWLPjTAejU-H1Lnn2jWQeHtiRxBL1eleZNmJVqFbrgclcMXirM6rrmPrsbFe41fDF3Hm1KgcKkpZMPSICijfDCT4csVeLDxmsg9aDYwboxigOVHZa-zAmePLBZrPJIWDNEHNBG9CdEG-RfeshvnRbPerB1zLzA9jP-Jj55_Xd4igau4FEc7dLWgyn2b2Q3aMAaDnKCzEScd301WeuZtutm6flzqDPCUTJnoniUHuO__bALWkzIxe5rHW6wQ_wPBEX32bQNN-gtI6_yiw-UTwu3egro3tDp7ZzHkMSslF9FHD7divbmeEzsE8N4iOwO5kWFt2jY9VpjGXAhyCcGZtWU68SzllOpWzvuacFjlE5KZ_c4nHhYdaphJAjXvbkog-vGUwjffCXe9gQhIliwPzREtccZdgyLKiBAlypp0pwVKe6disU9-2kflk_BXPRf1PkBEqO41ySFZWLb6eSij9FrIXtPAo4RFmeKPLoYT-ce3gi8_XftVv7MDl9s0hoFlgh5vTh1xMdpxEt-6BxdesEF3zJycxNY4QFVkUKE78geXogQFz2QE7kW4ncTXjq4IydHOKX9Bp2P8uGcCJ6dzW3PFE-Zurf1klV-rkvT7xE-Tds7CPeWkrRr_Ckhn6rQ2Z3-Sjz5bgIRHiBnd0iZfm6ZgD77nVHY7ztaSmUQ7JWbeFSz0eoYExgXi7HfSdV77DlHxIjcNlrSh58SGWfkSwUVboOUJKy_B3EbBDeweqn1pf7QIjAJnYL7WiogmAku2UxEBQijtPAusmyhLf0_aTEFFc3zdGutHim3dzAKfJucy2aBm8ViQxY_U1N26WVO6sfui7dZVhqkQniZLCq8N_xqEMqWV6utksRHOvITvB_SqmeDacy2ZfiSogU8K5G2ha2NyZWRQcm90ZWN0Ag",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiNGw4ZGlzVjZWaXRHQ2dfRUp2Q054N1Y5MlFMdEJuX1JZcTl0VEJFWjdqNEI1aFpJOWtpakoySW5MeFFOUllWbGdMUk9GM25majgwWWk3TVBoWFF3anciLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
            },
            "type": "public-key",
            "clientExtensionResults": {},
        }

        challenge = base64url_to_bytes(
            "4l8disV6VitGCg_EJvCNx7V92QLtBn_RYq9tTBEZ7j4B5hZI9kijJ2InLxQNRYVlgLROF3nfj80Yi7MPhXQwjw"
        )
        rp_id = "webauthn.io"
        expected_origin = "https://webauthn.io"

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=expected_origin,
            expected_rp_id=rp_id,
            supported_pub_key_algs=[COSEAlgorithmIdentifier.ML_DSA_44],
        )

        self.assertEqual(verification.fmt, AttestationFormat.NONE)

    def test_verify_pqc_ml_dsa_65_packed_response(self) -> None:
        credential = {
            "id": "S903soghFo9Bmu9i4Styf5hLEPFkxu_Ma8Nm65BiZdBt1pGqF4dB2cth6wknrCMk6A",
            "rawId": "S903soghFo9Bmu9i4Styf5hLEPFkxu_Ma8Nm65BiZdBt1pGqF4dB2cth6wknrCMk6A",
            "response": {
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkIIHSm6pITyZwvdLIkkrMgz0AmKpTBqVCgOX8pJQtghB7wxQAAAAIAAAAAAAAAAAAAAAAAAAAAADFL3TeyiCEWj0Ga72LhK3J_mEsQ8WTG78xrw2brkGJl0G3WkaoXh0HZy2HrCSesIyToowEHAzgwIFkHoNsFUCfZJHghYZMYm8P_ANG6RtvE1VKrK5_ER7yE512V3UmGjIlYVOSIMebtBorke1TBvjuBi8PBKAQs4w16SJ7ijjT8r9ClCt_aHcFDTjz49s3jLIwqL08wPD1qJy6vrdkTES-mrU6rJG16RAhInZh4ie98DGZhBBaOUBIrnIy9QvceP9Qi8-4GBLcBiS-cL_da94kK6XZJXJLy1Qm-LfDPdsoph0YHGSfueYBJy41Tpu6oU4QStJ90r_E86dxQj_nd0uDPuwbje_lIrF0sbedrkNXVOwh00m-PK05fmwb-wpUUGsRq2o7gvm3oCMSxm-1dwYHKdBWjf8y_E34kiQ_ZeZTsA1yXSKci7kCEGGXqLDIE0chka6hY6xZZlEA89Cbqv_HPAN29t0_70144qDuXb4nLfQ7XY-uoS5OBP_W0rkc3lc3r0spe0c9ZO8lHEGFbX8PyP98gkM2z61kDstai23k6OjLTKMvuulKNYbTxCLTj37BpiNxnqqq5bs0dkG9eO5yHpqBwH4sm4qUXRsG-ZS9_TvfiEtKahjU5uAhZWOYs71CcCIfSKSD_swPg-7VKUwzSpYq2BwlExdBpDHL-ghogYAOgf5FNs9fUNHLRmFpOUDnmUAeX7iNrtA7Tu3BygNv8JWUCTuWllzT2GQpD70xJMAjKxMkvXrqqCfJrFTQt0FscjqjZqcP8xyiaCo0nPILaGChuakL0XBgh-Fi5YkulKsaDd5orLnka4063lpn0jdxvy1yk0p4tfFRmEBnankCmk44ZvbKJQRMsDcydqgjK0vpQxVWbf1r-73GHNvliWw1ajYmqUe2uwDGdLBBCUbDeqcmrRJYnX6g8W-vlh3VLWGBlHodtGWUEkJxY7RmArf2UeEBDGWj3QoGJTfQYUzXg91Y2fSmgi2b3ZPzUg8h92JKMCpbvJr6PLANCFGf3RviLYnNuU0Zn8czC80tsUtxkkzLN0iFkRvT_WPha6lbuwIlMKNXkXRbkph79wSBasp81aqzgPd4Yq9LDrZIrNI6q7ZbYGoF03C0Digqdj_f6aUxxIteIuCWm-z_xHY9Czo4VHo0V8YnTFyZj3HDX1S8NZ_odvP_GZcmvgLmUhsWRmMxs2WEJFDrcgFR-tK9KLYf29gGI0lPsSJtnho_GLUKX5-tdojlBVEcVO6rPieS8-bCu8B4BeyduYAnDgHdxBAUBfm2um7ZIDTl_n6g-bZb-TxMvsGbIO3NK99QylHqSRFK68PX-yvDZjsZlblKZSe8WsSG_RVNrWGYiKjVpsqZy61eXoSE5ySCOQvAdlpTEdb7F5C1_USkpdyuyR5BGXtFizf2V60wDPbjOrr3Yz1CuUB_DRDvbvc4GKIAzCZDR6MC3oIJjQ2Z81pzv8ZrXq5LhhSdda2TTBtckM-BRyLJHh7ZkHY03DFLqfGSn-KUzGlk2fUWFdJ4zlT4AquxJTKJYBQlWt6tOgGV8MB5j5DUuwgbw9a7dx_jRW8AZps4O96y85c-rQS7e9g5noatqxq1vZp6X-vTTMZXF-nx1sgSHEgoN5bm30fsrMP0MvaahDZaEIV3o8kj7o-uRM8VGyXVHm3qhtQdYIwzrjWBCA96t7x75zgmgxIWJbzIgfay3WHeguFIwW844OaO_zq3C43tDCXU0ahWiTjEPeYqAVDGlifqOPEFpiO5t9lvwjU5upQybkhnwLzFvaUVCgzGu_2bm7geO5NphNee8lz7Rbi4r8VBCzDYBLcjeqMiUCduCQH8y3mo3Z3F4V0qqAUHM6w_hMr8V9K_mGNeSYDEv52bBHxfywJkcqSTq3TVkPXicWfb1VHJroZ47LdAQ-jlGJaTnJEfHeY5VHHjy9gQ6_px7iZ9JggN0SIJDbSdHXHxkdFbSgMnEHo8N3YFoB-oEO5AKX1CJ3kELg8gO-nybVMC4ktDqk5dAAglVcp5GQC8gY_EP92LAXt4MFHRkM9g4zgZHVlqKLqbPPYngB9nOAM-8rZGo3Nez0zB7m5EFDkxV8PoD0k2omrJEqWrSDd9swG6kFiH4-5MV-8csaka-PO0kwS-KZmbh7R-OhJlmKujJw6nxYDfUaPeXQs6QsFqU83BZxl5gZGr8LPmqP83i1tEk1RQd_pwFa-ks7GmMvWQuyK2PnaW9cXfH-0-Z-jetukzac8KqTOkdedYmeTPW9oHlGmPvAEBvoGNQeUzw5Q_uwBv60LdbEpy61iiTQNEy7eKDxylHJld41P9vTTh1om6TEWGmHJ1BQ5YLoZ1E_X4dnMZGZUtcK4Ym_81jHMdRw4NkdQhPtPFe5kfPYMdIn_QeAIVIS_KPyo07t_9BhrDfRBirl_BfAGpEdVuwZQYO-x-jZ-0WGXptAp1TpmAVjD2Y-Gwx4xRL-Y-M7NTaTAeZpEB6_UdQU8UUL_DfQLxlF6dE4Px_0xmPAXBNtZJIWcdOIOIpnjP2vvT39x4SgoS1Ij7udQZUoidhA6M6_bwOT3uimKVm31vLH-tN_N3eMgQj8Db2Wj6htO0Ysk58ueKGN17UruWYPnktWiR-M3hZs5mJKlxHeVwTEcZgkIqYM14Hg0IB8M41ICy1vhrEzO9aQ1Cwn36srly2-h_coWtjcmVkUHJvdGVjdAI",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiclFNM19IdHdCNjNnbDhFb0xxck00aVBDbVEzc2lXOVU3UnV0bnc5cUdNWlQ4bFdBRVRJYVpjRkV3NmoyUXc0MGZER1pXNFFyYmlzQmpvUmJlWGlkTHciLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0",
            },
            "type": "public-key",
            "clientExtensionResults": {},
        }

        challenge = base64url_to_bytes(
            "rQM3_HtwB63gl8EoLqrM4iPCmQ3siW9U7Rutnw9qGMZT8lWAETIaZcFEw6j2Qw40fDGZW4QrbisBjoRbeXidLw"
        )
        rp_id = "webauthn.io"
        expected_origin = "https://webauthn.io"

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=expected_origin,
            expected_rp_id=rp_id,
            supported_pub_key_algs=[COSEAlgorithmIdentifier.ML_DSA_65],
        )

        self.assertEqual(verification.fmt, AttestationFormat.NONE)

    def test_verify_pqc_ml_dsa_87_packed_response(self) -> None:
        credential = {
            "id": "OsaaaMgQ7ihU9iAzryPBOLK3PYsghC98pX4ZaDzXzY1NsiXgH-afxzClNy3oRPK1YA",
            "rawId": "OsaaaMgQ7ihU9iAzryPBOLK3PYsghC98pX4ZaDzXzY1NsiXgH-afxzClNy3oRPK1YA",
            "response": {
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkKoHSm6pITyZwvdLIkkrMgz0AmKpTBqVCgOX8pJQtghB7wxQAAAAEAAAAAAAAAAAAAAAAAAAAAADE6xppoyBDuKFT2IDOvI8E4src9iyCEL3ylfhloPNfNjU2yJeAf5p_HMKU3LehE8rVgowEHAzgxIFkKIPB266vR3jhFEvswhiiULf6og2993LKO8euC16EFiq3z9bud2jKbB6Zw5xm7vOQUIZyCsN18qxjPRoI142swvpDA4rApAGZb028Qgyrz4eQTfueiBsy-GRJ5IN2rsVlFcz3enbYWgh_UWQDSMA9wNfTPJZPz6T-z8KTz60szO8Mn4UG1kLQ5YSV47b6LqJVnrsWzTFe0nylAkpHMtBHS3UNjhoEYNc6HyL9ehBoLGs3Z0IPusTYdcZ8LA4icQsoX3X8XEORW4MV5x1l9qwC_6-iZ4rAsbSUsUMDyB_h-FKn7TP9X8x_IA6fCDuUIL2vMWwVj-yNtVbw_NqJkm5OePjPQzh04F6wxLd4y0qeLZA7ycjADjACLKa_IJVFMgxx_7nJ2pbHKOYfqJzAnCg9nqMUVeonWBunJatFABgwKR4-cNzV6pcn1bL4haHbHdblbZ7f0nv7-DPz75BaZhDaurOBLBHGDh5bC856v0EkPOfRO81pKBa-EyT3OkZ7qejOMeEZpbvhCvECisLwbKo8lcAR0gaqHLNGEXcqNUFXVbLzdfcrDd_FMD-kBByAlGdMswYANrFpLVpmkJEGQ_Eqow99ZcyBvdwxtxCQT3X4i3rFRhB8FGP9JAkODC67U-EWIMyWF2VIseVZkxMngwsZAm327jFIoOfupWeUGjpGORhOvI6OPA2VzR6wrFjkfsM_6bt8VMHIpo5lUtGMKND5K2M3fRCFvQqPWW7MOQ83b-6qfa-GcGKzVfojGd6uwVJjgDDJldMMve8OCTktiwIJ4h-n5ObGRvlJQ7etgycCwXINUkb1KFZovgUQnujhjK4f0M0Ib76scKCmYX_UtexSCf09jkwQRgtBh3BnzJrgILfErMmfK2Z1z5wWUV4MX2oXcNkWyGGH1kCLnzXu1qveFsry7Hf27DyceNIAzuqkrtcsJgw7ePhXHz0AgdYo8qyQmXSPfhAEWiwtCZ5MbUKmxn-8pGiRKqUtbzpYTNwTpj2PdpzK1zvAAHubIxi5XXi_JEJL8h2HOmkRJLLo26GDfNV0n0SRGhujW65LNdAU7ggrgzEcdbkRPNX0vsyax0ZBr9HXs-GnlR_4ySugcgGVIdj5xv7xsvDnfy-bVPMLgOP1nCLvZROJwMAA3XOAD9SKjsQMLKQjsiZHIelWzOxHrr360wowj3jclxQUD9XgDtNfff6MjiS3rsBO05ECyF3bMcsjsRak7GStJ2MFBAbdESryKek1z-2g4ahqUuO0LGeX7Klzi110XpqN9VYrrvUNP6seqm_V48PinvDDPsfsHqC2ZFPRtWv3rcZt6RbA9KLsqXqWphMqr3MZm8k69E2ZiWn-wFHXMBWTKzrRxtiBOHk4mcygTOIn2AsjVMO8GCglyJlUluN0eQWiapr48lnE3EetPNGxq86wn28wPQhC56jcLkNHq-RDEjycvFzUzgoa4i1mJCW038vHGPH8-CLYGggPeSOnL-zZMRtw-jDaMR5HHc95FlsTLlMVbpnb-eCGT2-khduVx4HdpdoTJHfT4PNQTTVnVY6N5vUP9x5jXq6p7Zwvl_VpWR9jxZZcO1KIoi5ozIgE5XqNF-NKumoouAfpZWxauhdkBgUL86WnH3zQah8hHY1d7QeZGcfo4fx8S0NiTsVa9wIat3BBlck3HmwbduMP7Web7Rhf_Pj3lfhVrZ0p5nKFizbacQcK4mVwCM8MPaFEN6xAIwqLzFYWIwc_sUKxRq2WLg3RvIbBl0-TesJfzSPWMJGcq4iropcn-JW8XFQVJyf4KBFuwImpXq1wrOalOjIgAk5nGiYxLxK3feeOoG22uBNkfg_qJfqzGX_o3BMaXZyvydAQCY36z2SbFEme3LxsdC-vYUi6iVuxVdpL2gXm3OtNiI4iGvBNoJvGzHZwSh0-GpZbqdN_wZMFimvz8R75O2PPXSkmyLyDmNxDaSGsnZeQ4BCyD63YLnhFlWzG7VBIdAr570KEz9dhU6ozJ6iP_mtETAImGWB733xuIeZ2D3Aj-Q9l2s2xfPKqPXkvOe2OjC288A86T5l5_9mANfFgfLCjdsMwSQau_EOkrvmPkaHacBoWPfPMWwyBJSnF6jNPHoaRBtFba6Ld-f4ThJyaza52JLza1xIviFn37XzFCvLRXrpI6wghURUP2vk-dMs1l8hQRH3RIvcBIqctikAL3NuY8otXhQUw-1QjkIv2llYeXARAhE-2bIvATrf7FrVN4hJBbU3uesAyYvpG9NN8XGztoptOotFP_pYH67yUaiYJXmnPTzWEzk0F5kUhZTvy7ZlwKMv2EINrXDc0q1Dx0MJnJSe02PQr2C0RzR0zkTi00-y104KimThbs7QLRgnke7BlaJtgJH7T-KETvLqs6Ogpptzntt6whM8lesXUvQr5jm3l0WLCSo1W8-q-Vxfo8v6cbkHxsP_xoM43uOsklCuypxyVfnBRVGsgL9W5_7TaZTWMdfoak9fwMjd8j1lu6oXmOiu96TQ8vpETLuN4A1AOnFS1grl1dBZ-kUoKV_vu4ZFDkacK20S8Q5X-WcM5zKmpVUWL3oyWg3VNxSDu_16LLPQ7pYfgS9dNftCHnOjYUgY2Co_xD0ejB83G-a3aC-OSBwo7NtOHTfh6gysbSzBwsJ0Tw9GyCRRLqpu4YsWGkJXiblfGI-2zH8aGm0GZLz84p8FqRCipTbMt8yjFjKDoCp3iBpUTfMs3uON28otSpkgF5XPIwihK7O0Fu8tw-DMLXbbxMDxyAhto3xGb7Q1KT_-hc4SrghI4dy_Evm095K6Fr3sHsQ_oVck2xd71r4e_uPCXFpiHbvImwtuE94XyGgy9y1l2TvRa6P1ZpKh-ccxv_v1TZdf3gIn04M7kio46WfIiURcS6aoVfCef1pUpGRcVgxnwWrJw_8tu7MZUukXmM3SA7dezKIe446WE6BiXay7TNBu9yThxldO7ooK6udljaap3pEyejRWNJ83zSVv5OwjlvDtC4joCHJ6BejJh60OM0KeiMniTJftrV4F3ZRMgn7MdbJtUYOY4SoodNAfPEBr5n_6n7ZCT4uBAsLtyYwHmzjIR1qZxOVfH98C2xOrp6ZWFMiAlrJkPDoiD8sMMB6oWA2aT_vPcixKBQqNqrkeKScusIiThNCTrlK5AkDe_AqUEW1qu8E6Qbb-7YLCrhqIbMmg5eGKXZ7c9j94jd-rShqUz2seWaLAXkKi-VMsUdTnlgvQ-A_6IRd8wM30BpVQeDuS-AE3cfnw8poVsuaPsMU5me9Ro1um1GUEU8mLzSw6ZMgHlbFapubropKvU-2-s0nozxQzs7bh4NkPF5gZ1zuf7xNXcPV3uodzJnmtBNn7lcfJK69serkxLEKOa7IiS2osGQlxDh9mwwMip7fuVPhN9ZWadhWnrFlWfdKzv082WxErNeM_SslKaeg8UJPzRYllQ1szvS3pYyt8u3JSX2z6FrY3JlZFByb3RlY3QC",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSnNHc0J0SE1ZWEFSVUlvUjFySHZhbTYzWERkUkR6YUxLYm5kcnNjcGdVMHFLRnBKQTB4ZXV2X191ZmtfNW1naklhYkVabmVPOVYzMllXeU1zaFdtRUEiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0",
            },
            "type": "public-key",
            "clientExtensionResults": {},
        }

        challenge = base64url_to_bytes(
            "JsGsBtHMYXARUIoR1rHvam63XDdRDzaLKbndrscpgU0qKFpJA0xeuv__ufk_5mgjIabEZneO9V32YWyMshWmEA"
        )
        rp_id = "webauthn.io"
        expected_origin = "https://webauthn.io"

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=expected_origin,
            expected_rp_id=rp_id,
            supported_pub_key_algs=[COSEAlgorithmIdentifier.ML_DSA_87],
        )

        self.assertEqual(verification.fmt, AttestationFormat.NONE)
