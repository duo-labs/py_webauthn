import json
from unittest import TestCase
from unittest.mock import MagicMock, patch
import warnings
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    encode_cbor,
    parse_registration_credential_json,
    parse_cbor,
    parse_attestation_object,
    mldsa
)
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

    def test_verifies_mldsa_attestation_response(self) -> None:
        if not mldsa.is_ml_dsa_available():
            warnings.warn('ML-DSA not installed. Test skipped')
            return
        credential="""{
           "type": "public-key",
            "id": "ZAm5To5dRDuoBHlOoo5Fl19jcnlwdGFuZQ",
            "rawId": "ZAm5To5dRDuoBHlOoo5Fl19jcnlwdGFuZQ",
            "authenticatorAttachment": "cross-platform",
            "response": {
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQTB1RHlWTkN1Qk9vbmstTDVWZDBxVmtDOXRxNzJfUms2S09kcEF4eF9OWSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkFekmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRQAAAAAAAAAAAAAAAAAAAAAAAAAAABlkCblOjl1EO6gEeU6ijkWXX2NyeXB0YW5lowEHAzgvIFkFILCau9eCTbGwd15c9JemK6obEtvxDREnBm_KMEPyiKpO8Z-MmvkhJzLO62SOHHPLxnLcsgpQ_rmCY-Yb2VKDfREPyZdXAoVEkBYfvVReEac6cPI3rpfLyJRCpTNhaTziAjfmvgAKiO62I-d6cvGYkp-LZhuW-qBIkYOUxf-Flg3aWKNGYGIymVtNnG7wa0NeUXYnuPWsbYAsjwFvbKtJcmJX9sx1WPmI79u_m73hPK2XWGogFa6ngTG0KETf9lIruZBsZLSOi4YWkRLYZ9JISTziZeze3eknIUSssJ-JvU7GyB0YwhXfNfcC4tDl9AAST451_OjFvRY_xIs1LSKwf6t6nsaZQjKJGo6lMDO78WofyEQecAs7yv7DIWdB2oUt9ysT_w1Q5OfYDTuA0k1JxrE74yq6JFEZ6oLFeWczQNjJpnQ3UKIYat454XEZsxF47_fBuwV4HuiRj9lRJhOxCiDTkZ874VtItD2ESgCf9ADrfNyzDWXWuU8SuJ_xc292N1iTeBK3XkoGHDzyaCF-hQPLsW2LBL8bfa8z8V0kfpjvqkJmR1N4aEAyYDiW_L_AA4pZ8tUqWWnMXL9YtfU2osuUjMm-nnNdgvl_ScR5gVeuzj_Et1srG1iGisPi-zGxOtoOex2_hZ1UvXIsP_5szIMGgJoVgok-hNgJLj0jJ9QP9txIfv0zhpiRGiZy1UyZ7NBNMYcWevmif1RESqulcAh6GEvgdaS0nROZUsB-_qT8W4CaJA89DfbdqJEiw2CntCJEnbR6ZpOHYSEFWJVMIz4i1pHsnipFLIMxfpi9afSzO8RqPqXnkYghFQO33IuywxUhVQlxWlH_13Y58leHKqAYFW1TJ6JtY8b-8D5Yb4b46gOwEQpA8iFDgeFMSj8MHEr31OUchoG4skw0uGQ2PSfZQGn_EjdNaRaJeNz4C8Rz8EhPvkQ7MR2s40dKcE6_Sn_YciSA9XWHYpnGlDlNgeZ7WGjQpIjCtX1w33LYYJ26ov1sv7E9qN2ffydEN1S6mysEkS88ogKJQJNYkG8MLeWqAjGgHJAVcMAwTuG3pLu_PPse4ZZ7yphSOjgldoVv6nSD_14VafXPC4-RjgnHKNimIalipUuT3gcT__wjcMAUsa04QNRx-cmijvy6No0ZA5J5YZ3SOIxpjdkGZ6G1L666aiy8oLdxnzKfEbcm-4j-TybuKgRKCzpf2q1FLB2ddLDYa6mk4cYH0ABggNaL8AT0n72W40RSEF78Tbo33PSsqTD9CXBIJ1lZ9tI513v-A4iw02v7buOXd56p0vnCO75lJhcJfu18G8wGcgPx41ZEEYpzjEkPWO8vlMC_Edx1Tb8pS2Jrx_XOLejBV80dDng9n5EAlxveoWL2dxoozSYgvp47okDRTcm7s4YQLQDuKeCckjl5wOUoFDjBt9-PB26U3RNsc9nlxXu5y6YNcrfK3G2qF92mrMYxaNk-6MOHsWRK_JWD2gG8eiA5QmvvNmUYyUpmCFLiJOnlJBv22ucHHJRyHbslQbwtnGsZZXNQhWrd50m9eBWM_11mys9WnI8Yj669a1wKu7F0ab--nHWpJwGMdZRFkCklL5mm-ZJFSToj8S9BjfUeNwrx8t9NVy-d6RYKU1lFBKxYKP3w24AMLre9O0Yd8QH9YMwM0RNsk21Tzpb-xqqONfRUDpfbbjo9N-9fKZD-Ax0yyWcYHWs5BBc6OosjuYDr1mRa0gJMM4OcnjDFOjfutK2ExLFH13Y",
                "transports": []
            },
            "clientExtensionResults": {}
        }"""
   
        challenge=base64url_to_bytes('A0uDyVNCuBOonk-L5Vd0qVkC9tq72_Rk6KOdpAxx_NY')
        rp_id='localhost'
        expected_origin='http://localhost:5000'

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=expected_origin,
            expected_rp_id=rp_id,
        )

        assert verification.credential_type == PublicKeyCredentialType.PUBLIC_KEY
        assert verification.sign_count == 0  

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
