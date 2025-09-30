from unittest import TestCase

from webauthn import verify_authentication_response
from webauthn.helpers import base64url_to_bytes, parse_authentication_credential_json
from webauthn.helpers.exceptions import InvalidAuthenticationResponse


class TestVerifyAuthenticationResponse(TestCase):
    def test_verify_authentication_response_with_EC2_public_key(self):
        credential = """{
            "id": "EDx9FfAbp4obx6oll2oC4-CZuDidRVV4gZhxC529ytlnqHyqCStDUwfNdm1SNHAe3X5KvueWQdAX3x9R1a2b9Q",
            "rawId": "EDx9FfAbp4obx6oll2oC4-CZuDidRVV4gZhxC529ytlnqHyqCStDUwfNdm1SNHAe3X5KvueWQdAX3x9R1a2b9Q",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAATg",
                "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJ4aTMwR1BHQUZZUnhWRHBZMXNNMTBEYUx6VlFHNjZudi1fN1JVYXpIMHZJMll2RzhMWWdERW52TjVmWlpOVnV2RUR1TWk5dGUzVkxxYjQyTjBma0xHQSIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTAwMCIsInR5cGUiOiJ3ZWJhdXRobi5nZXQifQ",
                "signature": "MEUCIGisVZOBapCWbnJJvjelIzwpixxIwkjCCb5aCHafQu68AiEA88v-2pJNNApPFwAKFiNuf82-2hBxYW5kGwVweeoxCwo"
            },
            "type": "public-key",
            "clientExtensionResults": {}
        }"""
        challenge = base64url_to_bytes(
            "xi30GPGAFYRxVDpY1sM10DaLzVQG66nv-_7RUazH0vI2YvG8LYgDEnvN5fZZNVuvEDuMi9te3VLqb42N0fkLGA"
        )
        expected_rp_id = "localhost"
        expected_origin = "http://localhost:5000"
        credential_public_key = base64url_to_bytes(
            "pQECAyYgASFYIIeDTe-gN8A-zQclHoRnGFWN8ehM1b7yAsa8I8KIvmplIlgg4nFGT5px8o6gpPZZhO01wdy9crDSA_Ngtkx0vGpvPHI"
        )
        sign_count = 77

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            credential_public_key=credential_public_key,
            credential_current_sign_count=sign_count,
        )

        assert verification.credential_id == base64url_to_bytes(
            "EDx9FfAbp4obx6oll2oC4-CZuDidRVV4gZhxC529ytlnqHyqCStDUwfNdm1SNHAe3X5KvueWQdAX3x9R1a2b9Q"
        )
        assert verification.new_sign_count == 78
        assert verification.credential_backed_up == False
        assert verification.credential_device_type == "single_device"
        assert not verification.user_verified

    def test_verify_authentication_response_with_RSA_public_key(self):
        credential = """{
            "id": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
            "rawId": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaVBtQWkxUHAxWEw2b0FncTNQV1p0WlBuWmExekZVRG9HYmFRMF9LdlZHMWxGMnMzUnRfM280dVN6Y2N5MHRtY1RJcFRUVDRCVTFULUk0bWFhdm5kalEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                "signature": "iOHKX3erU5_OYP_r_9HLZ-CexCE4bQRrxM8WmuoKTDdhAnZSeTP0sjECjvjfeS8MJzN1ArmvV0H0C3yy_FdRFfcpUPZzdZ7bBcmPh1XPdxRwY747OrIzcTLTFQUPdn1U-izCZtP_78VGw9pCpdMsv4CUzZdJbEcRtQuRS03qUjqDaovoJhOqEBmxJn9Wu8tBi_Qx7A33RbYjlfyLm_EDqimzDZhyietyop6XUcpKarKqVH0M6mMrM5zTjp8xf3W7odFCadXEJg-ERZqFM0-9Uup6kJNLbr6C5J4NDYmSm3HCSA6lp2iEiMPKU8Ii7QZ61kybXLxsX4w4Dm3fOLjmDw",
                "userHandle": "T1RWa1l6VXdPRFV0WW1NNVlTMDBOVEkxTFRnd056Z3RabVZpWVdZNFpEVm1ZMk5p"
            },
            "type": "public-key",
            "clientExtensionResults": {}
        }"""
        challenge = base64url_to_bytes(
            "iPmAi1Pp1XL6oAgq3PWZtZPnZa1zFUDoGbaQ0_KvVG1lF2s3Rt_3o4uSzccy0tmcTIpTTT4BU1T-I4maavndjQ"
        )
        expected_rp_id = "localhost"
        expected_origin = "http://localhost:5000"
        credential_public_key = base64url_to_bytes(
            "pAEDAzkBACBZAQDfV20epzvQP-HtcdDpX-cGzdOxy73WQEvsU7Dnr9UWJophEfpngouvgnRLXaEUn_d8HGkp_HIx8rrpkx4BVs6X_B6ZjhLlezjIdJbLbVeb92BaEsmNn1HW2N9Xj2QM8cH-yx28_vCjf82ahQ9gyAr552Bn96G22n8jqFRQKdVpO-f-bvpvaP3IQ9F5LCX7CUaxptgbog1SFO6FI6ob5SlVVB00lVXsaYg8cIDZxCkkENkGiFPgwEaZ7995SCbiyCpUJbMqToLMgojPkAhWeyktu7TlK6UBWdJMHc3FPAIs0lH_2_2hKS-mGI1uZAFVAfW1X-mzKL0czUm2P1UlUox7IUMBAAE"
        )
        sign_count = 0

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            credential_public_key=credential_public_key,
            credential_current_sign_count=sign_count,
            require_user_verification=True,
        )

        assert verification.new_sign_count == 1
        assert verification.user_verified

    def test_raises_exception_on_incorrect_public_key(self):
        credential = """{
            "id": "FviUBZA3FGMxEm3A1K2T8MhuEBLp4qQsV9ScAKYrpdw2kbGnqx24tF4ev6PEHEYC3g8z6HMJh7dYHe3Uuq7_8Q",
            "rawId": "FviUBZA3FGMxEm3A1K2T8MhuEBLp4qQsV9ScAKYrpdw2kbGnqx24tF4ev6PEHEYC3g8z6HMJh7dYHe3Uuq7_8Q",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAJA",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoienNmaU1aajE2VFVWQ3JUNXREUllYZFlsVXJKcDd6bl9VTmQ1Tm1Cb2NQYzRJMmRLWmJlRVdwd0JBd0E0czZvSGtWWDZfbHlfamdwNzQzZHlpV0hZWXciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                "signature": "MEQCIBX9B1LaLaQ0LYJsRv7cOyMS-Do1rJfFJoF9oO1tHMA4AiBRKdNneMKPlN53i8uoTZ5y9Gj4ORZySmiercS38655_g"
            },
            "type": "public-key",
            "clientExtensionResults": {}
        }"""
        challenge = base64url_to_bytes(
            "zsfiMZj16TUVCrT5tDRYXdYlUrJp7zn_UNd5NmBocPc4I2dKZbeEWpwBAwA4s6oHkVX6_ly_jgp743dyiWHYYw"
        )
        expected_rp_id = "localhost"
        expected_origin = "http://localhost:5000"
        credential_public_key = base64url_to_bytes(
            "pAEDAzkBACBZAQDfV20epzvQP-HtcdDpX-cGzdOxy73WQEvsU7Dnr9UWJophEfpngouvgnRLXaEUn_d8HGkp_HIx8rrpkx4BVs6X_B6ZjhLlezjIdJbLbVeb92BaEsmNn1HW2N9Xj2QM8cH-yx28_vCjf82ahQ9gyAr552Bn96G22n8jqFRQKdVpO-f-bvpvaP3IQ9F5LCX7CUaxptgbog1SFO6FI6ob5SlVVB00lVXsaYg8cIDZxCkkENkGiFPgwEaZ7995SCbiyCpUJbMqToLMgojPkAhWeyktu7TlK6UBWdJMHc3FPAIs0lH_2_2hKS-mGI1uZAFVAfW1X-mzKL0czUm2P1UlUox7IUMBAAE"
        )
        sign_count = 35

        with self.assertRaisesRegex(
            InvalidAuthenticationResponse,
            "Could not verify authentication signature",
        ):
            verify_authentication_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=expected_rp_id,
                expected_origin=expected_origin,
                credential_public_key=credential_public_key,
                credential_current_sign_count=sign_count,
                require_user_verification=True,
            )

    def test_raises_exception_on_uv_required_but_false(self):
        credential = """{
            "id": "4-5MZF69j3n2B6Z99dUN0fNrAQmrjELJIebWVw8aKfw1EQKg28Tx40R_kw-1pcrfSgJFKm3mCtAtBgSRWgDMng",
            "rawId": "4-5MZF69j3n2B6Z99dUN0fNrAQmrjELJIebWVw8aKfw1EQKg28Tx40R_kw-1pcrfSgJFKm3mCtAtBgSRWgDMng",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAAIQ",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoidW1HZW1YSklQQlhQeGtEOEhqYW51djlCRG9yOFo3TzNhUGR0T2dNQ2RXNFBBZnFEWDQzRUZsaHJzRjBQVzkwZGY1enJnYnQ3WVZNUkFhMjd0Q2RIenciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                "signature": "MEUCIGp5ADnU_SFvT4J_bKvQJ4Pc1GmANhbYq5GioOLjyUrxAiEA6Kk5qAZb8MLY-jyTiJLr_R9Fke02UHkxsRB0dnZt2X8"
            },
            "type": "public-key",
            "clientExtensionResults": {}
        }"""
        challenge = base64url_to_bytes(
            "umGemXJIPBXPxkD8Hjanuv9BDor8Z7O3aPdtOgMCdW4PAfqDX43EFlhrsF0PW90df5zrgbt7YVMRAa27tCdHzw"
        )
        expected_rp_id = "localhost"
        expected_origin = "http://localhost:5000"
        credential_public_key = base64url_to_bytes(
            "pQECAyYgASFYIOQ5TKpXJR2cV76Wgfge9BkLkEhLxVjhFjM1jKHYOcqpIlggaiNy1blt3OU8Hsmg041HUYP7eajgL7fk3nSuTEjYCwU"
        )
        sign_count = 32

        with self.assertRaisesRegex(
            InvalidAuthenticationResponse,
            "User verification is required but user was not verified",
        ):
            verify_authentication_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=expected_rp_id,
                expected_origin=expected_origin,
                credential_public_key=credential_public_key,
                credential_current_sign_count=sign_count,
                require_user_verification=True,
            )

    def test_verify_authentication_response_with_OKP_public_key(self):
        credential = """{
            "id": "fq9Nj0nS24B5y6Pkw_h3-9GEAEA3-0LBPxE2zvTdLjDqtSeCSNYFe9VMRueSpAZxT3YDc6L1lWXdQNwI-sVNYrefEcRR1Nsb_0jpHE955WEtFud2xxZg3MvoLMxHLet63i5tajd1fHtP7I-00D6cehM8ZWlLp2T3s9lfZgVIFcA",
            "rawId": "fq9Nj0nS24B5y6Pkw_h3-9GEAEA3-0LBPxE2zvTdLjDqtSeCSNYFe9VMRueSpAZxT3YDc6L1lWXdQNwI-sVNYrefEcRR1Nsb_0jpHE955WEtFud2xxZg3MvoLMxHLet63i5tajd1fHtP7I-00D6cehM8ZWlLp2T3s9lfZgVIFcA",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAABw",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZVo0ZWVBM080ank1Rkl6cURhU0o2SkROR3UwYkJjNXpJMURqUV9rTHNvMVdOcWtHNms1bUNZZjFkdFFoVlVpQldaV2xaa3pSNU1GZWVXQ3BKUlVOWHciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                "signature": "RRWV8mYDRvK7YdQgdtZD4pJ2dh1D_IWZ_D6jsZo6FHJBoenbj0CVT5nA20vUzlRhN4R6dOEUHmUwP1F8eRBhBg"
            },
            "type": "public-key",
            "clientExtensionResults": {}
        }"""
        challenge = base64url_to_bytes(
            "eZ4eeA3O4jy5FIzqDaSJ6JDNGu0bBc5zI1DjQ_kLso1WNqkG6k5mCYf1dtQhVUiBWZWlZkzR5MFeeWCpJRUNXw"
        )
        expected_rp_id = "localhost"
        expected_origin = "http://localhost:5000"
        credential_public_key = base64url_to_bytes(
            "pAEBAycgBiFYIMz6_SUFLiDid2Yhlq0YboyJ-CDrIrNpkPUGmJp4D3Dp"
        )
        sign_count = 3

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            credential_public_key=credential_public_key,
            credential_current_sign_count=sign_count,
        )

        assert verification.new_sign_count == 7

    def test_supports_multiple_expected_origins(self) -> None:
        credential = """{
            "id": "AXmOjWWZH67pgl5_gAbKVBqoL2dyHHGEWZLspIsCwULG0hZ3HyuGgvkaRcSOLq9W72XtegcvFYXIdlafrilbtVnx2Q14gNbfSQQP2sgNEAif4MjHtGpeVB0BfFawCs85Y3XY_j4sxthVnyTY_Q",
            "rawId": "AXmOjWWZH67pgl5_gAbKVBqoL2dyHHGEWZLspIsCwULG0hZ3HyuGgvkaRcSOLq9W72XtegcvFYXIdlafrilbtVnx2Q14gNbfSQQP2sgNEAif4MjHtGpeVB0BfFawCs85Y3XY_j4sxthVnyTY_Q",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFYN-Mog",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiNnpyU1JYOEN4d1BTWEVBclh5WEwydHBiNnJCN1N0YXIwckxWSWo1cnZmNzRtWktGNWlyNzE1WG1nejV0QV9HeUhleE40b1hmclE4ODlBclZDTGFSZEEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                "signature": "MEUCIQDBqeI274exaKWGQz37g7yo1--TVcZSCcYVftZ1AnEJkQIgNw-nlx-_U9rVfFfER8oX6BlYZTuPFyGaL_wCDY23s0E",
                "userHandle": "TldNMFlqYzNOVFF0WW1NNE5DMDBaakprTFRrME9EVXROR05rTnpreVkyTTROVEUz"
            },
            "type": "public-key",
            "clientExtensionResults": {}
        }"""

        challenge = base64url_to_bytes(
            "6zrSRX8CxwPSXEArXyXL2tpb6rB7Star0rLVIj5rvf74mZKF5ir715Xmgz5tA_GyHexN4oXfrQ889ArVCLaRdA"
        )
        expected_rp_id = "localhost"
        expected_origin = ["https://foo.bar", "http://localhost:5000"]
        credential_public_key = base64url_to_bytes(
            "pQECAyYgASFYIFm1Py-FzzFOuwXbRbTr95SiDxuB1BkZsEEJxFhquzqkIlggL1U1T713Jo_2muzhXvpbwRNdoAs8CYK6PflvY1MBdCI"
        )
        sign_count = 1625263263

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            credential_public_key=credential_public_key,
            credential_current_sign_count=sign_count,
        )

        assert verification.credential_id == base64url_to_bytes(
            "AXmOjWWZH67pgl5_gAbKVBqoL2dyHHGEWZLspIsCwULG0hZ3HyuGgvkaRcSOLq9W72XtegcvFYXIdlafrilbtVnx2Q14gNbfSQQP2sgNEAif4MjHtGpeVB0BfFawCs85Y3XY_j4sxthVnyTY_Q"
        )

    def test_supports_already_parsed_credential(self) -> None:
        parsed_credential = parse_authentication_credential_json(
            """{
            "id": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
            "rawId": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaVBtQWkxUHAxWEw2b0FncTNQV1p0WlBuWmExekZVRG9HYmFRMF9LdlZHMWxGMnMzUnRfM280dVN6Y2N5MHRtY1RJcFRUVDRCVTFULUk0bWFhdm5kalEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                "signature": "iOHKX3erU5_OYP_r_9HLZ-CexCE4bQRrxM8WmuoKTDdhAnZSeTP0sjECjvjfeS8MJzN1ArmvV0H0C3yy_FdRFfcpUPZzdZ7bBcmPh1XPdxRwY747OrIzcTLTFQUPdn1U-izCZtP_78VGw9pCpdMsv4CUzZdJbEcRtQuRS03qUjqDaovoJhOqEBmxJn9Wu8tBi_Qx7A33RbYjlfyLm_EDqimzDZhyietyop6XUcpKarKqVH0M6mMrM5zTjp8xf3W7odFCadXEJg-ERZqFM0-9Uup6kJNLbr6C5J4NDYmSm3HCSA6lp2iEiMPKU8Ii7QZ61kybXLxsX4w4Dm3fOLjmDw",
                "userHandle": "T1RWa1l6VXdPRFV0WW1NNVlTMDBOVEkxTFRnd056Z3RabVZpWVdZNFpEVm1ZMk5p"
            },
            "type": "public-key",
            "clientExtensionResults": {}
        }"""
        )
        challenge = base64url_to_bytes(
            "iPmAi1Pp1XL6oAgq3PWZtZPnZa1zFUDoGbaQ0_KvVG1lF2s3Rt_3o4uSzccy0tmcTIpTTT4BU1T-I4maavndjQ"
        )
        expected_rp_id = "localhost"
        expected_origin = "http://localhost:5000"
        credential_public_key = base64url_to_bytes(
            "pAEDAzkBACBZAQDfV20epzvQP-HtcdDpX-cGzdOxy73WQEvsU7Dnr9UWJophEfpngouvgnRLXaEUn_d8HGkp_HIx8rrpkx4BVs6X_B6ZjhLlezjIdJbLbVeb92BaEsmNn1HW2N9Xj2QM8cH-yx28_vCjf82ahQ9gyAr552Bn96G22n8jqFRQKdVpO-f-bvpvaP3IQ9F5LCX7CUaxptgbog1SFO6FI6ob5SlVVB00lVXsaYg8cIDZxCkkENkGiFPgwEaZ7995SCbiyCpUJbMqToLMgojPkAhWeyktu7TlK6UBWdJMHc3FPAIs0lH_2_2hKS-mGI1uZAFVAfW1X-mzKL0czUm2P1UlUox7IUMBAAE"
        )
        sign_count = 0

        verification = verify_authentication_response(
            credential=parsed_credential,
            expected_challenge=challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            credential_public_key=credential_public_key,
            credential_current_sign_count=sign_count,
            require_user_verification=True,
        )

        assert verification.new_sign_count == 1

    def test_supports_dict_credential(self) -> None:
        credential = {
            "id": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
            "rawId": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaVBtQWkxUHAxWEw2b0FncTNQV1p0WlBuWmExekZVRG9HYmFRMF9LdlZHMWxGMnMzUnRfM280dVN6Y2N5MHRtY1RJcFRUVDRCVTFULUk0bWFhdm5kalEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                "signature": "iOHKX3erU5_OYP_r_9HLZ-CexCE4bQRrxM8WmuoKTDdhAnZSeTP0sjECjvjfeS8MJzN1ArmvV0H0C3yy_FdRFfcpUPZzdZ7bBcmPh1XPdxRwY747OrIzcTLTFQUPdn1U-izCZtP_78VGw9pCpdMsv4CUzZdJbEcRtQuRS03qUjqDaovoJhOqEBmxJn9Wu8tBi_Qx7A33RbYjlfyLm_EDqimzDZhyietyop6XUcpKarKqVH0M6mMrM5zTjp8xf3W7odFCadXEJg-ERZqFM0-9Uup6kJNLbr6C5J4NDYmSm3HCSA6lp2iEiMPKU8Ii7QZ61kybXLxsX4w4Dm3fOLjmDw",
                "userHandle": "T1RWa1l6VXdPRFV0WW1NNVlTMDBOVEkxTFRnd056Z3RabVZpWVdZNFpEVm1ZMk5p",
            },
            "type": "public-key",
            "clientExtensionResults": {},
        }
        challenge = base64url_to_bytes(
            "iPmAi1Pp1XL6oAgq3PWZtZPnZa1zFUDoGbaQ0_KvVG1lF2s3Rt_3o4uSzccy0tmcTIpTTT4BU1T-I4maavndjQ"
        )
        expected_rp_id = "localhost"
        expected_origin = "http://localhost:5000"
        credential_public_key = base64url_to_bytes(
            "pAEDAzkBACBZAQDfV20epzvQP-HtcdDpX-cGzdOxy73WQEvsU7Dnr9UWJophEfpngouvgnRLXaEUn_d8HGkp_HIx8rrpkx4BVs6X_B6ZjhLlezjIdJbLbVeb92BaEsmNn1HW2N9Xj2QM8cH-yx28_vCjf82ahQ9gyAr552Bn96G22n8jqFRQKdVpO-f-bvpvaP3IQ9F5LCX7CUaxptgbog1SFO6FI6ob5SlVVB00lVXsaYg8cIDZxCkkENkGiFPgwEaZ7995SCbiyCpUJbMqToLMgojPkAhWeyktu7TlK6UBWdJMHc3FPAIs0lH_2_2hKS-mGI1uZAFVAfW1X-mzKL0czUm2P1UlUox7IUMBAAE"
        )
        sign_count = 0

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            credential_public_key=credential_public_key,
            credential_current_sign_count=sign_count,
            require_user_verification=True,
        )

        assert verification.new_sign_count == 1

    def test_verify_ml_dsa_44_response(self) -> None:
        credential = {
            "id": "-EM9FDFIdFVeqWdTycRjoZVN2ZS4vnVE-MBpg7k0pl4jpuqj4GnMCW3Wqlm2WWI2PQ",
            "rawId": "-EM9FDFIdFVeqWdTycRjoZVN2ZS4vnVE-MBpg7k0pl4jpuqj4GnMCW3Wqlm2WWI2PQ",
            "response": {
                "authenticatorData": "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvAFAAAACA",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiSmkxNTk3MWpTRVNhOWhhQ1VZYjdzX3BNaFY4RE5Od1lUOFdiNXpiRW8xNTFBYjdzX011VC1fTUlqbm91c2ZhRjJRM2VtRkF4N0drcFhrVFVtTWljVFEiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0",
                "signature": "e7L-Xli-2lj9ZlP2s26sbrvFGLkVrz74BZnDsLW-7HOhj7AcEl5Zgtm3VLvLtcrfqyKE0PTuFrswsikm7t6ddhxXphxWcSo4ggarl6ODQk8NdPCYoFhoK8qwpqKZKmJAl9xDsJE1HAudrWLgq_747JV4QmGLizK0_oJgGM7WLd5xVYvKsl14odBFjU_ZBCrjB0UHIMg8aAq1727yZnY1eiNeF_sEmci_pigYCo-MbxbHmQWPp-U75sGSPPfK0soN2-29_aIxRO4Fg8P37WrwVUrEFdG2PFNgAhcM-ljjyv3mkCfsLUiQNuS-a0cn6MeygREc2HBwE6ChS351-dpNTbkfnb-o1fA6suP1sh3-i7YZrEn9e2J7UZxIAEJPpmuKxYFA4Fj0lAGUhi3lvnkWPOnS8BUjPr5q5z5iEbyL4MokDP75G723Tyy-5L8u1pLmlSLiuwvuW5MBkEhjVVj0RpVSnCoqzwE9A9ZmqZx5wv5gQEi4hAA64mSoXGdUZ5EGkPGrrIDjGyIOrLjuHOSZ6hjyioZvMA1nCQJ76oaL5-Pn1FR1VTurI5ccTWrDAo5sHuo8uGjx9bsyy_aMT3Nzosu29PArTm0AkJFd7INXky0L9itCmhujSnali9zTO8UuwV0G8sZeB2BG4VZN2nkjT1Ib8VeBnSMTlIFVOI2JHlD9kePZuV3nCuAvK8j5qH5OPJoEeJzuxGHP2k7f0941kzyW9sjBaD90HEusVGGgST0qWigEKU3kKaO_Du5ZngcqlmKnnFVKXQk5mEV5nFs9ia76sKe9FKYUp_ZxsVFATcjXETW5GuXF1qIj0ZTCSmhn8V_cqEH29fQWyy9qxNa6kkKc4koZUP36B-h5yVawIDdfyjl-VueUvUyEunPv1EyqXQaf9bo-WThxD_5v3Bd2sYTOI__0PIsUvCASjZJMQU4jpwyXoR2EsLWDRD4fsAxLmdao0iXNxdlH0Ys2MqkXkkMbIylccEHkFjbm_VB5tPYQkFRqqRX13KUyYqqTpaT6MdD8IpltlzJxcNLd9mazUvOfSaf5ho2FFtv8TMubekKU8b92MoPQpjeS1DJ9y2pvMrtIiZP0Lm0WTeniN6luRfUN-4v5GU6FPajkOPLNV9OXJKLREhrA_SvbDldSF9RtWZOqIk1WeTlbnEWlejtwWFoLSScCSfExu6bu_vv9NKK-E8mTWF8_f4bCvlZQp58BEsTHrZuBiQzH34Z5wPeOZuuQlqbAquIS4_W6z_XmNW-d4FhIp2U3y9sYC7wpo1M7N7MB3HKwAliPVgsNHBRI4ZLZ-dL3FCyCMThKJqQMNrMcRif_Mm5Du--Atjn1UH2u2gAxiBA6IY7uSlSn-OJEO-m8qeif8zsdvVhXtJMxNAWZHhQ4QuRFgjuDgxy1nVuhGHdmXi6tseiiC2NQ9iqGuBRetexfz84R93RVSbKMkYlvBU1KPe8ARVf_N52C1KC9F2b3Uo5To9iD2lXShcsGkQkcAX5gjmhy4jrmTv5-pUJYAHa6A9Vorr59D7-Y-CVvVX59YJB9-kMT8wzHQdj2XimbcLKnS5Z4BKsMMEIt01LVkdHcBP9tKBQ20e-Kmf25wsUr9TqFa7ukQEhfLwgflIBbobAJoGKFC2_3fIKaEBuoAOoErASxPClLNAbBqG1JAdrAq9Ki3WC46aN4b-Q6ykfbk2azLAxOzFftJuhLWGLLCkOxbxjfaUrRJ51h8Dwrpy2xBT1qWurNnfFTrzScouK-R8G4SfsyaSiejiaLYLsWZVCcpeH_S8cqQuBFCMpQfxiPn2reOgMFhSzbdSDkzwUTQsjGq94QTs7bdS0LlyRb4OUa0s3szGSIa7n4vQ10uc9gzHlDxEqgaKSpPlVDyvZs58GC3PCZ2HJiiVbuc508_rV1xuydd7asPlyaOAMXImKPxp7d6rAGLbDOQOKS4U9sr6wKQVPnfPqg7TvmtuXTJS5Y_M6mutU7Bn8y6qmbjt5EtoETTSORHfx71ySMLZ8zxveJdsaNow6lfjvI0myk8oSDIucRar1j9G2m13B3K2Kr0URBweH6JkJz3Z7mYFTe09B6GMzIOcPoaYzzJP_PSrpuAfvb6V0AwVCX_HixF2qkCvcdrLyvGaGkkkYh32T2Renu7QWj8Wz06MvimWYCA4pB8SPJpjyw8mNZHOWJXgkI8hgD90O_rDF8mhEIMbDtfTZdOPjekS1a7-LNUGM6ajWLzDehU5YQBzTuGwgoPd2RV0E68iYR6QplHTmhh5vToa7eHvbQrYn8NUzJ6CP5YXcoxl7H9HsQ3AXDHmCtZ3e5p4FLV-Lz64_hVJWaTLOgHecFGAFqXMmnp1BtoKlzwbMnXaFMVaT1T7CkC_XZsoggQA1WFO3vFuXpnw4D6BPNGTmEZrEmINmfBVeFHB4SHDPJXDYX4wwTK8kgUpCHSI8ozIYFy0nw4uJqhkAYjXnvbEeCPsPkf7SPGS7xujgIdlYbtizeg-op2ZyI020Jt-hx2GogXRD_bsNcHaToWZ90fTI8M_Y1-F8iMJG4OnxinHlHnTj7R6wRuM2AZ4-Ov_yhd9w6yXenoKh56RReHCbYAvGCt3aDDyOrcX9WX7VePrBHH3C9ubCwj3PNcuP16or5ho6XRNlXC1s63J99dgi42FWatXeYdUvvcmK7fKxFZWSCXko-cArTT1KqgucxXg8wMk7gaGSwfb2j3pNt1hf4y5MOJQ-HbS0uhuywUbBiHBe8ns6FzUJpM4T8sNXAfbslBk1nIYU9BCMn1Veqw8puCYcwkjWJgxrKU_d2Jx0b8DKpIbbdFKkrdR4vAGRTJ74IgWPuk7wZTSWCddJAB4Q1PU1nbXO3MsxxzlQrWXY1jD9Zp3E69NEUss4qMTT6u5W-RG6RB6ge6sOt47l40v3IO-1LgsCwJtFyQzks0msArf0MSSQ9HreubNnjYqaMOqgUleX4-a0P8BhQwOhwt7C6zyGCnbcBiQx0RWAs0mvf-k5mgqn9Ij5mpGoGVV5L4OhBdY6pm51h7v02bgoWlzUzZHImgBhQtkx0jlBM9XeCIo4t8EQ4ZbqGmLsbj3CTu7KZbc9uQJkWyXSov2WWMvzZfOgCHbizXOGazd47v44BDRMXIiUmJzI1ZXiFkqPB0NftBw80ZnCHlpeq1Nzq8_QQHiM2R1SEsc_T1QQcSlJTVmBpdnqesbv9AAAAAAAAAAAAAAAAAAAAAAAAAAAAABMhLDo",
                "userHandle": "d2ViYXV0aG5pby1tbC1kc2EtNDQ",
            },
            "type": "public-key",
            "clientExtensionResults": {},
        }
        challenge = base64url_to_bytes(
            "Ji15971jSESa9haCUYb7s_pMhV8DNNwYT8Wb5zbEo151Ab7s_MuT-_MIjnousfaF2Q3emFAx7GkpXkTUmMicTQ"
        )
        expected_rp_id = "webauthn.io"
        expected_origin = "https://webauthn.io"
        credential_public_key = base64url_to_bytes(
            "owEHAzgvIFkFIC4AIUrgARve17AEk0W30POluaL08p91eLXkktSjmAlmZdNTWhtUFj3wkseZEt4xpmWarG28Za86i7yq-B4df3uOuq3zQVTKOQUWJLWGJ3-wUUuyywPtkdgSqzQdcli6xMgwnVqh9r6FVL9Xp7x3kgjUVDqhux_k1D2d4ts2zqi1rUrSF6FNX139g3dd1VnUNQrMLdrwohR9CmE0fZ6Am4Df_OV2JxOrUEPzMFi5SeBcrU1oSj2lX_91gY179PO0wIOtTa1KzWvwOYa_KjOj9Ow16AtmsXrcpL-jYW4_bFn4kpT9G-vDG4qPFDpint62g0DDjEt7JrF288aIZXOpsbVmnjw2_O_5pFFvFpH32gD7_NdmvE6PSymNxPcTCnMzY3xv5wJXiEDhO21E85n78Oay4k7PzWHvzQxlJldIYw-9TfKZXqZa6sIbE-LyZj_Y2FV1Owd4WLvKCNcO-IIP3XFcZ7__XPZtAsBTJ5Z5w18jRnlMNKTygva-F2Ec65tA2skED9PnVyS_WjtZN5VjbhuU-D9DIDXEgUjitdcXWbCruDjxaBwjuDFXOI9cYdp4n-KWCZGJdX9QFHDGkvX6zDXupFrFV1q1JeKCayuMJjL3Z44AMF2UtjNODzhlviE8neX5NSfXdf36FWGFER6D6YCGGvooW8EBCx8OLPRNGGwoKBrEflr_ISYIdyw8-rDkAG0-bka_ulzfg8uTY8BXNu0HhqsteUPni4HlhUXMb0yI1DbLi5hTTkpBEBfmjzTJ8JMDe9sOOaqU2PrOzvIs5c7fx_VBqQZbF6amei2Y41okZJWwW0LWNvL2JQ_Yj9deHMczichCHWVX3uCL-SfPL3AaLeWLPjTAejU-H1Lnn2jWQeHtiRxBL1eleZNmJVqFbrgclcMXirM6rrmPrsbFe41fDF3Hm1KgcKkpZMPSICijfDCT4csVeLDxmsg9aDYwboxigOVHZa-zAmePLBZrPJIWDNEHNBG9CdEG-RfeshvnRbPerB1zLzA9jP-Jj55_Xd4igau4FEc7dLWgyn2b2Q3aMAaDnKCzEScd301WeuZtutm6flzqDPCUTJnoniUHuO__bALWkzIxe5rHW6wQ_wPBEX32bQNN-gtI6_yiw-UTwu3egro3tDp7ZzHkMSslF9FHD7divbmeEzsE8N4iOwO5kWFt2jY9VpjGXAhyCcGZtWU68SzllOpWzvuacFjlE5KZ_c4nHhYdaphJAjXvbkog-vGUwjffCXe9gQhIliwPzREtccZdgyLKiBAlypp0pwVKe6disU9-2kflk_BXPRf1PkBEqO41ySFZWLb6eSij9FrIXtPAo4RFmeKPLoYT-ce3gi8_XftVv7MDl9s0hoFlgh5vTh1xMdpxEt-6BxdesEF3zJycxNY4QFVkUKE78geXogQFz2QE7kW4ncTXjq4IydHOKX9Bp2P8uGcCJ6dzW3PFE-Zurf1klV-rkvT7xE-Tds7CPeWkrRr_Ckhn6rQ2Z3-Sjz5bgIRHiBnd0iZfm6ZgD77nVHY7ztaSmUQ7JWbeFSz0eoYExgXi7HfSdV77DlHxIjcNlrSh58SGWfkSwUVboOUJKy_B3EbBDeweqn1pf7QIjAJnYL7WiogmAku2UxEBQijtPAusmyhLf0_aTEFFc3zdGutHim3dzAKfJucy2aBm8ViQxY_U1N26WVO6sfui7dZVhqkQniZLCq8N_xqEMqWV6utksRHOvITvB_SqmeDacy2ZfiSogU8K5G0"
        )
        sign_count = 7

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            credential_public_key=credential_public_key,
            credential_current_sign_count=sign_count,
        )

        self.assertEqual(verification.new_sign_count, 8)

    def test_verify_ml_dsa_65_response(self) -> None:
        credential = {
            "id": "S903soghFo9Bmu9i4Styf5hLEPFkxu_Ma8Nm65BiZdBt1pGqF4dB2cth6wknrCMk6A",
            "rawId": "S903soghFo9Bmu9i4Styf5hLEPFkxu_Ma8Nm65BiZdBt1pGqF4dB2cth6wknrCMk6A",
            "response": {
                "authenticatorData": "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvAFAAAABQ",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiMDRvRmpNVUd6LUtCQ1ZYUWFFSnNMSGpuSzdwWmxPQUR4R0hld0Y1Skc3X1U0cDVmczBtYy11S3c3cmd1Zk16UGlLMERlYVV5OXR6djhrVkRMT1Rhd2ciLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0",
                "signature": "dHOT781bYCrWW4ZOQmVjfVVlv5Xh-KN56EAIjE5sWU7pyXfhmz3mrMXf0CwqXVb_bifjCdqW8luipsAw00gcNBZNojEILkTiCAygrj5iwYt42_7n_8KZ6t96vFTsOSkqHStzgbXR-seyb-MqRp1y6rjZN0OLsnruUGv5D_xf5IdXecN_O6BRBP1J1zmBsLvwDPyAU_EZ1fSMMheERqxE9_E07qe9HP4vSUWt8pyt0mPRZlxtePZUrL76JVwTp0w-9u9vRGGWDgfg1YFD4QF4r8ZuOj2r8Z-7Jzd8z_vBjRBcRt9j0TegG9YrlHJZqqh32loh1j0v-95Yvq0PG3IlCp3Nq-39dUZU0QugtComdeDvsGKgNBECh3vRO_G8y-oaaNLRzRquw1uBVCtX6atozdFXAiZRzB5vwjjbVocgCtxinN3wX6GoiKRbPNzHSyn_s_orCcNAS41SoBAw-QFh4VR4-VJ_iYxnGxXquQ3khGhhCtcQm_FNmADTsPosuoThwP4yeHgqohgtP0Cn-a38AnpDKCKOGE_YdnXMe3UA3MTzXKTDeBVpfscdecMf4m2Jdl7xn3mj1TdkaIXboVkVa6aqWwasDQmN11i0C8InlcculCrXptd5ZkiwQ58SfeZOBqA3_McEAfkt45HfbdVHpXMC7VHM9T5pVBnf5xeF2rrraH1SlwtFUmpNMoNeHzMI29_G4cXTChLQzPm6mKe5Nlcfif3hQAzbf85y4wZKtgmhKlT_YZXBhoGA-4ImW2_OfCxPn_VZOtDVnz-nr7Qpqy8GY_K-rQUrWuu9X6Bxkz9jwhoXpwEPC0YTZGWcxIiioxlO6iNGqcQAeGDJj-cgh3-2crtUUCvVrK05qJDHbBDRgj6zWWKrS1mFPY71kmAjakm8QRTHP89TkDBw1AGcsLSYPH973a5QQUVvjy2pKvnXL2FTHLtCoXWiBSqntDIZ8L0NCLxkNEO7HVnUMM3sg44kdrftz2WDxCU3qZ5oEBrQ6VLKKvNsAOx3Cm07NPB6mKbAPuTg_VkU38AecRbHtcPAsFjPPXD4Yys7GUfMl6oD6V58G8WKbPG74PSkdtNmrJRceFc4-P594kFH3nwEKEuzlIjokXpEPtqUL9zKKAbRe_T8tMvXBHtaRoNTkNzqUPV5lblJ-o5gPvNq9vRgcIJlPCAaQFFyfo586Ee9_zYcAKSqIyIRgT2JQhMXShknVJ_9BAx_Ho_E_HirRuo_1FacQOzW7pXxkrPXuP9aL9DXNCDv751E8lpA4wEKO9vW76kTVaIFH7V6AD8MKFKkX9Rzvqsz8rlgF9LhdYUf1sD1pbbSlA0npsPkIdM9fvaJHTqKcqt2ZBMCFl5JV5ZayPDXeRJvIl7xASj1y_vUqMwxzob8N3mqticeLtk-AfW1TapU1GqUEJ_7XWu14sKxDaVOg61kH0pUTXkQ-nkW-SbIHW8dD7kwWen4UNnelNR7grgrLiKN_hCmcjibrhCjQyCmsdvJpvqUl5dwunSF-DYNnOGrsHQA6h4Cllw2Ttf_eH7Z2FRavFMR_3C2da-qjfx8tN5VMg7XY02MoyN_BbBjXx_QyGef8QnrQz-EfB05w9EZdwKcRSjAjdGdwms5m7BHEaavKsVXxdHIta1My54YKGfZa4B6Kx1XdwtUGoK6VZcjcS4mv2OxjfbdKuQaeUEEq1wdlb6_SE_TRWhbzj7LiJjn37OhIyZpFxJwA4UtUkKnayBn3iAZTaSc9LkBDguzx43A1kCzEU1x5cNmJ_q2Dg8k9aBYY_7rAMyhf4D7-iCcv7IHq-WvnMCUzBt9oZfnNf867KkAhjXSG7fXiChvkwmW7FR-_hQuC1IBSWzs4VnJMdlOBYnqE30H80QyFmkUkcvxtJlensw1ZjoTRKhc-22N3HGybRLZeGgmpQ_6qwCVu0HiJRcEl7JzMHqfZAJ93S-PH0mfC9BsjpS4lYpSmTjtjwSZNweW57OcVVmy0bLlqtMFzT-xguv5ppLqWP26hV3hz478YsISj3puASohrwc9zGF90Kt3ND7vpt-B4Mb57ic4c9XX6FqzjQLLaP43HtHautrFNAUuQhbTwg-zup4vp1jq4G0xy9-QKu9GaJtc5heDqSu6W4i5eGJl5YGpvYH6ZHYjZCdi3vnl6z3e10aSMlWznCdVtmNKk45oEbToXDnovEtjIHFvUgMCN8vEOKEIUilX1wGAYfxQfFhKlPrwUfcJlmM4P2v51batbeLLrOOE5llBMZsoF6P8WgbJgtw9iB45ddLrFX24Yw7C7pbwJeMr-hVZxkbT2CUJbpcPYx7URr0yxa1mqJJDHfx7lT979jZG3gFLUDA9towbiFX9ocWcjp4fwO5rMy1OEMPQo1n0k8eZpfXino1AjFH4RPVziExeBJhj4esKAHfUOoI1mKhnJc4S_p_VTlR8VcECl-wzP-esBsGi_gYh74SeZlVaDxitEVE8kH_BHBAiivU6hP3OhV7ykxuwnS8G4RlO7d-9F3jDqFqzDME_RY3YIk987UWlpOdWTgA8DXKcvbjZLbB4QJC_D-Pz4OW_xXFRqJYlCmPkGfpJw5n6Z0KVPi2Uy06yM567tOox3SAYWdww6vKK8Ntkto5mT0sMLmIPSz65AKUP1I719D4ckY0fkAFJpFROJiDSbtexqRAOXwQFTu2IAuJ5PuUFecCletfveZh-rHMi49xEYcBltM55bZMtYXwUHtk_WM9rsG3Ob9q5veBTPTMNrh63yeKHQmWM60bVJX6RdPoRlBEUb44_JWh_H3RiN0Jct3HsKilvrN_91NLEAmyK6LHt0M-x83lOizFhtFlVQj7yFKfQMDS-qgtGdE8OitBc5Edvc5P0Ye2kDK74Die7Raudj38jv391rRzL8UOoRS_XvSgxaKhZrj6nfu0uhjPC1OneGnhLbOET4Pp_iRs1aKeNhj6Iu5j_Yp64iVUq267ueZ8cya0dXyFqWeR2HnuCmgd7pLr8ZGh6xphG8Nm3O1Da-up-W5zrQehKw77No8MxM6rSSxwGBgbyVaZIXnAJOhRovIImVk5whtuFMDkD5rQgJKYZH1-80YIHQh7XycA2gdXdaUHNZXIQ2aQf4DtddPVLfJaNJR_UO_ZROQChqG2k6IcelcySFvcOiddeIq1od6QNFZo2eMX6_J67K1H1uAmf_XVuuuihuKtSUfmt56y-BY-PBnlD9dtRsl18TIVjvCVRZMlYCpYXO1SIbStJ9EaX2ZFAPIilXN9qg0i8ZVxhtjQtlWvgWywbRoYbGH_hYPfHuDTjihNBLXWsUa5AoXaPk0RnbHSf0-7oFEuHwbWPVtmqS4gZtxS3g163-0pi4FtAUq80lOMGY8FNGtH_4AY9ttZFEhgBeBdytil2GhpQJyyx0Vk4NrPJ2863E7egDzz68qsnxooRXOjiLNxdR5mgGn_JYEt_IkkFpf0eQhrdilM6zq54-bQUiOW78wOkjbn24z1E9l7xpsRH15NtO007sfY5IveC9kFeGNBBhaoUCHFSrcu-jFzXjhOh63D_dEMiSZbWwpatiDZTMj1R3QZFtHMbgpPF-gn6wkHl3l0luFzBlKj5XQSQxJnM2JwKH6q4Pq8gq7xGeSL42sbOUahmgr6_Gg-8M4yXx9TeNTjpSI9aRS-PDwV_QpPJMRZEv1BqwsvqcwLAlHEhWaCYhqeMCHjqq5Hnbdw_pDc-cXOa6YrVKqIsj0jnM7OxK8ZHcLIZ7rdulp1sxtcan9T34tSO75K1mjGG0lVttwYPHG9ca8YBOF1aMHpR9tT-h4GsExmu7wkcZb68G8Of5Z9m39COU9O1SnkkQzGRPe9lRwkrbcZPz2kGSkmHYMp8OJjcidTf52zub6SVRmE6viXOayAnHndiirNRS1pjHi9NQWoCeZRBx_OAfhgr5_M0R88b18o79o36rX3IP6qMLOWWDwTNKU4uPvsts-jT9xSFohBpZiNvlPOdLVD9piBoJuBuwdOM61JttjdoEXlVnqI5M5uHZakhvWWWVApwrQu_gxZhL0insPOpud5gTar9F2G1tjSYoe8HgpraFppa-TpjlVdCJZga7H7nnLM88m-YDBm90FWvh-PgyXRtKqhQBSB2k92PC-d3PBUuNYydQ_AAF7a5NQFbCkDaC2rL8TzrHhop0kqWElXd60f8M17Qat3GddvWTMGzCtskeAUB6XYG7BJxoF_UjbArkaw0s-jltA2PcS7Kg0wVYpXlox8BbgA2qW7myBzj9rysoa5kCqPEKXc7ua08xWXoXEFhz5UW5baRwCwedL2klWUyUiRW9HJyz_OmVT171GYqbhxQwOVDKXFmT4dfl6f4TmB4x9UKM3yjp83bLlOSwO0netbf4enrCRwfKHwAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAkQFRwh",
                "userHandle": "d2ViYXV0aG5pby1tbC1kc2EtNjU",
            },
            "type": "public-key",
            "clientExtensionResults": {},
        }

        challenge = base64url_to_bytes(
            "04oFjMUGz-KBCVXQaEJsLHjnK7pZlOADxGHewF5JG7_U4p5fs0mc-uKw7rgufMzPiK0DeaUy9tzv8kVDLOTawg"
        )
        expected_rp_id = "webauthn.io"
        expected_origin = "https://webauthn.io"
        credential_public_key = base64url_to_bytes(
            "owEHAzgwIFkHoNsFUCfZJHghYZMYm8P_ANG6RtvE1VKrK5_ER7yE512V3UmGjIlYVOSIMebtBorke1TBvjuBi8PBKAQs4w16SJ7ijjT8r9ClCt_aHcFDTjz49s3jLIwqL08wPD1qJy6vrdkTES-mrU6rJG16RAhInZh4ie98DGZhBBaOUBIrnIy9QvceP9Qi8-4GBLcBiS-cL_da94kK6XZJXJLy1Qm-LfDPdsoph0YHGSfueYBJy41Tpu6oU4QStJ90r_E86dxQj_nd0uDPuwbje_lIrF0sbedrkNXVOwh00m-PK05fmwb-wpUUGsRq2o7gvm3oCMSxm-1dwYHKdBWjf8y_E34kiQ_ZeZTsA1yXSKci7kCEGGXqLDIE0chka6hY6xZZlEA89Cbqv_HPAN29t0_70144qDuXb4nLfQ7XY-uoS5OBP_W0rkc3lc3r0spe0c9ZO8lHEGFbX8PyP98gkM2z61kDstai23k6OjLTKMvuulKNYbTxCLTj37BpiNxnqqq5bs0dkG9eO5yHpqBwH4sm4qUXRsG-ZS9_TvfiEtKahjU5uAhZWOYs71CcCIfSKSD_swPg-7VKUwzSpYq2BwlExdBpDHL-ghogYAOgf5FNs9fUNHLRmFpOUDnmUAeX7iNrtA7Tu3BygNv8JWUCTuWllzT2GQpD70xJMAjKxMkvXrqqCfJrFTQt0FscjqjZqcP8xyiaCo0nPILaGChuakL0XBgh-Fi5YkulKsaDd5orLnka4063lpn0jdxvy1yk0p4tfFRmEBnankCmk44ZvbKJQRMsDcydqgjK0vpQxVWbf1r-73GHNvliWw1ajYmqUe2uwDGdLBBCUbDeqcmrRJYnX6g8W-vlh3VLWGBlHodtGWUEkJxY7RmArf2UeEBDGWj3QoGJTfQYUzXg91Y2fSmgi2b3ZPzUg8h92JKMCpbvJr6PLANCFGf3RviLYnNuU0Zn8czC80tsUtxkkzLN0iFkRvT_WPha6lbuwIlMKNXkXRbkph79wSBasp81aqzgPd4Yq9LDrZIrNI6q7ZbYGoF03C0Digqdj_f6aUxxIteIuCWm-z_xHY9Czo4VHo0V8YnTFyZj3HDX1S8NZ_odvP_GZcmvgLmUhsWRmMxs2WEJFDrcgFR-tK9KLYf29gGI0lPsSJtnho_GLUKX5-tdojlBVEcVO6rPieS8-bCu8B4BeyduYAnDgHdxBAUBfm2um7ZIDTl_n6g-bZb-TxMvsGbIO3NK99QylHqSRFK68PX-yvDZjsZlblKZSe8WsSG_RVNrWGYiKjVpsqZy61eXoSE5ySCOQvAdlpTEdb7F5C1_USkpdyuyR5BGXtFizf2V60wDPbjOrr3Yz1CuUB_DRDvbvc4GKIAzCZDR6MC3oIJjQ2Z81pzv8ZrXq5LhhSdda2TTBtckM-BRyLJHh7ZkHY03DFLqfGSn-KUzGlk2fUWFdJ4zlT4AquxJTKJYBQlWt6tOgGV8MB5j5DUuwgbw9a7dx_jRW8AZps4O96y85c-rQS7e9g5noatqxq1vZp6X-vTTMZXF-nx1sgSHEgoN5bm30fsrMP0MvaahDZaEIV3o8kj7o-uRM8VGyXVHm3qhtQdYIwzrjWBCA96t7x75zgmgxIWJbzIgfay3WHeguFIwW844OaO_zq3C43tDCXU0ahWiTjEPeYqAVDGlifqOPEFpiO5t9lvwjU5upQybkhnwLzFvaUVCgzGu_2bm7geO5NphNee8lz7Rbi4r8VBCzDYBLcjeqMiUCduCQH8y3mo3Z3F4V0qqAUHM6w_hMr8V9K_mGNeSYDEv52bBHxfywJkcqSTq3TVkPXicWfb1VHJroZ47LdAQ-jlGJaTnJEfHeY5VHHjy9gQ6_px7iZ9JggN0SIJDbSdHXHxkdFbSgMnEHo8N3YFoB-oEO5AKX1CJ3kELg8gO-nybVMC4ktDqk5dAAglVcp5GQC8gY_EP92LAXt4MFHRkM9g4zgZHVlqKLqbPPYngB9nOAM-8rZGo3Nez0zB7m5EFDkxV8PoD0k2omrJEqWrSDd9swG6kFiH4-5MV-8csaka-PO0kwS-KZmbh7R-OhJlmKujJw6nxYDfUaPeXQs6QsFqU83BZxl5gZGr8LPmqP83i1tEk1RQd_pwFa-ks7GmMvWQuyK2PnaW9cXfH-0-Z-jetukzac8KqTOkdedYmeTPW9oHlGmPvAEBvoGNQeUzw5Q_uwBv60LdbEpy61iiTQNEy7eKDxylHJld41P9vTTh1om6TEWGmHJ1BQ5YLoZ1E_X4dnMZGZUtcK4Ym_81jHMdRw4NkdQhPtPFe5kfPYMdIn_QeAIVIS_KPyo07t_9BhrDfRBirl_BfAGpEdVuwZQYO-x-jZ-0WGXptAp1TpmAVjD2Y-Gwx4xRL-Y-M7NTaTAeZpEB6_UdQU8UUL_DfQLxlF6dE4Px_0xmPAXBNtZJIWcdOIOIpnjP2vvT39x4SgoS1Ij7udQZUoidhA6M6_bwOT3uimKVm31vLH-tN_N3eMgQj8Db2Wj6htO0Ysk58ueKGN17UruWYPnktWiR-M3hZs5mJKlxHeVwTEcZgkIqYM14Hg0IB8M41ICy1vhrEzO9aQ1Cwn36srly2-h_c"
        )
        sign_count = 4

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            credential_public_key=credential_public_key,
            credential_current_sign_count=sign_count,
        )

        self.assertEqual(verification.new_sign_count, 5)

    def test_verify_ml_dsa_87_response(self) -> None:
        credential = {
            "id": "OsaaaMgQ7ihU9iAzryPBOLK3PYsghC98pX4ZaDzXzY1NsiXgH-afxzClNy3oRPK1YA",
            "rawId": "OsaaaMgQ7ihU9iAzryPBOLK3PYsghC98pX4ZaDzXzY1NsiXgH-afxzClNy3oRPK1YA",
            "response": {
                "authenticatorData": "dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvAFAAAABA",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoibkFCTmgtU3NkbG9tSUd1VXNSdldGYTVkQkdlU2dmSU5jcF9NY0dTMXlJV0lZZjRVdFY1bERMNnlFU3g5alo1bFlranJvMFlTMkRkeHpGOVg3a0l5UVEiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ",
                "signature": "-L6L4y8yFTMmIZjkAHjaOizc_6PF_paQqEaAbDBd4K7FrGt-e8bILnpFNDdiH48vyp4elFGHuK0hi4Cai0cQGwqiATL67CUgJ6a3hnFAdYkh7FZd8CcoRFqw-SeRxBNc8-KR7ALiZ3EUUrAHQJNNhUVJE-R-fafV9RRkBva31fDwHqksSuz5n0nOZvq9CqK9e78MflFMfhoKWNNNfCwjNOZdx-7m8RdDKx8X-B9RxEVBXeyOyDL8cAm67wGD-jYSzYppGCZV_qEiK350hWy00RgHcLU62_EdV7eMobWni9oAnZxLJw3mk2_hJketAL66PnBn5qtTS_hMyCPvcEf7WzRcdzE82LaMcaSfb14AW2l0qeSJBO4Q_MFe2zvq1GAw-q9HYA6oxZZagKQhqNp9cTqPEu3ivsOJB2jS5xLJhWs0ZGC6qh6WPWIYtOudBOwuFSJj5g18wRDXtHbrb4yidLlHD4DTPWSZx1TYFcWrwDXV9Ry2aaxTDCAHskXndCTFf0693vx2YA2flHSeGYgUhOsd6DmnGgq8a0c5Vv8zET_fIknh7QhLpj3xzo4r2s_P8j4dcNWrw20lGSVZGm6Erq9OiqTdit736jkvlcgCV3I7Buye51nIX-VqdAroEEds_-5TAev8nByqjSMM_WHygIyNnUJvPuzWkLSzDVl0hJiKs9m0pHyi4pfPA8RTiPZ7Ik0fPOG_KpvEytscHQkQvKxE5OMalknk1nrQPRmqQBC_RAYi-94zbYFcDO8-7Ny9NjmfO7gdz3lwj1BepKIhG1ggQMxQUNkM5zYNnhYlKQ_mNBsmORCvmxLg5EbqsqtNxORSYEG234N8wUFN2j7syzf8FyUbOdtLZNbTy_42Q0zs_Sww8YD7oNBuxWuCZ-UPIglh1aNhsLKjHoXLB3P_78R1zC1L-EFNAIBGkQL6mTZLHPu4iGH63D6N6xSIbfpw-XProqnQiWS4ejkUjf-zHZU1CmvkVqhFwa-TVCl48CPotPKwes146-4avolsoKtMrEhWXDLD11_e9xk94hb9w_fd8Arui8VCekXysn-_Qh5dYhbtGhoDHKzUyBsxYVojLaF2E74_2efAKOsCKnir0DFQWcQ0L8xClmv4C-bQ3HnAZK88sVyl6zDap2oEBXZHcRWOrb_xPGt6GgxEdUPFsWvoL_jlGNbjnpJyNHpVs1COoghB7SembOMF0tsGE2Kl7tG09Gd9q3aDOu3ox7wmYeBDDI0a8nvWrpMVp0olj5DU3A_x5fCQ0fdTpXI1aulVltJhgtwztsTmlAa3zMBINC2QeCEMu_t9Zjj5tNKXDQJ3mH0mD3E65DDQD8JeiJUFK_pdNIYAqq6xbmaW-SapDa_hF5rFMUXCc9hpxd1XijP64nsM3nvhkvUIjF1H_xxjxhFiAykYLy1SZLhpyKwr7r1faGIIG3eSIY3dlkXO6PdcQbTF4guw6jlILsHW1AsS3ocGrBPnHgLgjUmd9dEg7y27H5fSl0WQr6UqaH07gPvZ8Ah8GyrKUHfXan1vjkeLm6uaWv-x_klElMeFrO6DQPOC2JPpClslAoAxhBOpkr-si1sjrPTyew8U5dgyGEu9_kGxFK-o69OyR5H6-7iCoAXtPWQcBzzc3jhuUcvnGacqTMhJlR034FLKKPTZAG6rZ5oVsfhoz-2TJCc86TnX9gmiSONJX-PVgGZBOPvIsOBWsFuzq03yM5mACN_PLX2VnR58LjxQwfhus-GNIZt70_oHZn5BLLVfCvzhGSvpLj9OKF4B9BVNGg2mu4ChjnBXcgWf81PtDyT-jCls1gFN3VPq8QQKHn0xv_l0hBy_e7kugK26D50fA6JhtpDU05Hk_KS8Gu8dFZmsdKHjJEuByd6XezRxBYU4HZ33YnItElcmteN49e0lKBGX-RUdNXDd7A1Wi5UeP8yCXwMFYVZrDwhrEONBFOO97Jzn1KV6jGu_NE2e4rpMxnns0hHaWtMIdMI4Ao8-25g4nrhjZ2IsZuWyDhS57wlGO72C2DuncEsoW0Rl2EZEnslC7kqZcnpxV-winfBV0K-TVlOYaO7_ytgihDmfUv1j_PxUbV3IZBhxN5rU8il_MLJ5Geb5qt3i2oALZnGE_n4GmT0FdLMVXp6WrmaTIIK3TeSi0iju12eqGjPFPDRVdGh4gpw59awWREBd80Cx-ckfSmKx1nKcQ01pEl33VWMLRtlTgFjN6l1w3RBpXC21RWs7GbD8s3_M-4a3Dm18jBTFr4tOWWJKDlyVogNfw7WKJQGQ2k6m2Xj7OzXL6hEgT1KvVZgvTZrTNBkcQk2aYi-At0qBiX5gchZRsukvlCdEchDtkkRwuK4bvQ2PuVm26ycCWQIDNe27PjmjJuDZKgRblOvfWE_h4K1WQEzceg_wISF4xgNluKI9ByDdpecJHsccBDRfEP2CRu_FzHcMcl4bRrP3Jj23dKZej-k9j1MFrIJSW1lmDm4O_1aaYi25zhTYcJy11MvDGUwpymReCANK30HRsEp7VaCips6sbjJFIYV4UYAROEDreCHjOiHeeuMHtQD7jx3HDjSedxzcQtU123kOck7ptzzEnqqAPQ59C9nsPAq6oD9NPEqGA_fjjulpaXWt-fG3s3O-ltOXVJN6Feqp9LecbiYGQ3RBPQhHoRGYR_Kio9hIibuiTgwFTJGgFgNc-znvgAztDXFyuWbtDxnwLBhunpCHa2zNfZWcCVruypSL_GjTIsd2MJCmvJI5GFynIVRUfXjQuY-WKGAsXM9Cxr7IW9H1nVPegHqHSZN_-fcOUEGlOPCklJWZd4F2McDCXdVCmTos-OT01yiDEW6ppXMIT7TgJbXTMpFld3lDqpqDTxfhXIm3EFwc5lJqQ_x23yCQV8dth1rf1bpkiIjRSEl_p3g8vi7JHV8Ylda4XHgWJqxQJZeqHJP_f9MfzxOgC4H7IPhqt3LIT9HQMfNvsObOM1HIFd_mjOVfDF7byH7LppwYAQkGOkSvIOzggIZk-l4rXBSzx7YhPkKuc1GeGd5kzk3vZZ3PWvWUoquc9BuF8aJOtzltK74dMHAn7xyKIE-Nc2HGoA_n1ZI9SbM3HFl0ZP8SsOEbAu38wgyojcx52l7JZo25if-xnf1TKixzCR1Z1It_ovUgObfOuuC2vjAxCL7Ehxm4c3D9r30Q3BpqzzGppOcs2i7X0kznMKjnPFiAPJa4tyfCZNh2gvtOVUG707roZtN9RwGhzX12PwmhstsA_hoD4wkOfOfOD6cBIR9k493hxIFzb3aAO6ir91t2yk6TpoEmbZixJjj_KwdP1cnh9UVKrOIvpcjhawyCfqsQndWMqvAnaK_vHPSkjYh5FMzRiIpJQM8PTJ2yZbL-d4Mhl26IaXVtYK_NxrztGwey4BnN73qqMXXhmyvOweY4vzrW3eJPaifaZgfNZ7FNnOraEMbwf7jYq6ahJodQTA9JeLEEQL8G6XFhBUE48JkrL72woqfeXfh0iKlDUcV3YcjBP10MptDFCgXQmLivtDNPX0AtDQS0JXGb3yj92OGnzITp8LQlbyb8jwp4qF87ztF1u4GijPocJx41bAXWVC6Oupox0NbXgDy0wmS2GGwXLwRjvE9GGGJhNEk4JQRFnJf8ARGq_OMq3_CtbzBxaU1If82rtfdWcL7QT2zb127V4Yn7SawBRDknhwLWbC-HCJS2gAvdprToFRbs3UD5YR34fwFdJT96A5pZ_TMAXMIJVGS5rnS8LY2aFifY1-_U9J2LV8Dk86N1zgKWW-P9v2qmL2kC36_H4iLR4XAdjEulUXpy0MDxBupnh_-TAge0i-_DuLSny44KQ0xCNpRxsJI2dHwoW38VzM0vSbqzEWPqs9SqHDY-vQyUIl4zN8WNTcF-9fNkdqVY6pjvvPS6v9gIoGxun42lPa8xtakuPgr3MeTKDQ8VBAV8b-M6OdDq2esG_gnCgYX2SdqCei4aGLBkcMQqAr0K2M3VqN1UVX7WVchG0Ohtu44UIR1RJZergCG11A5LyJQ-sAkG27xB_KeI71HIuS3wet3kxldn1W1j1rNtchlyTdYfy_Z2AXwervsfetWZ4hJtrSFvPn2v5lC-mH2IjZUN1MaHrrhzRsM-T_PtEk3Xal8nuQ65XMBPwd2H0fmwaWPuBoFe_dSBsWpbb0OkChy_IrHyTHusG_CJP3ffRAEMNOKhlew_54VchYeEIPa10Vj2YUlqAit0-gapEavZ9bsqH051h3rnodjCsegRpoW9n-p8htvxAttoV7gkSYxaeSiMpe3w-kGnXDQYD3bnN4iDWZQU3df9Fg_8VABl1EBFlglGSiuOIa9bHViux80S0oCviAFooEl5KkE9xZD2Q9h17V1fW8mW4cc5GWkvawm-PUjf9n_YSqalFRuE26V8TWw4ig-VbymRfcvD7PF1JDguirCn7abWdvxxNxdeKleoglM6chOLEgPC-M4fkGOWfqxdF1b16jH2xE06QLL7HIfSwttcH-GOEAyU7vFe8tyPG1hgXJFF_GQXwtKIgHK_oHL0n_oVte6VxdcgZFRIaWxgyO6Q5X5m4JNWx8qqSAtNGx95f64Kt47U9usgdK_j9r3QO3Ojb6ylGao6PxdLJ2mkkdL_0A5HEiKQuoo9MPXiqPti6MpgKtY7EGlGYZahLmPK45pRourtxQOekXfSm5-dFRKbAqG0FVw1xOxmMRLPQS1a8DQAlurCNF3kHwCZSQwbo5o89SnCwXYgrPEMM4qAQ5-b1_NvxWUyIeEW8rXobfD_cpq1wDMk_fJiL3crYEmsRw6Uge9LHAeNecNlPpcjuFUGXqHDJtDfVNoNSygiw1-5dCWnkelWXge1a5MroSxRxIo31p4ba6sL9ZG04bkezX7l8o8Wp6VwS0ObUUBo1-MWwSzGXTn3wT7R9JKWQCzlHhfVl4GMmu3OTlNrhsQs8Nyugiu2jjAL6xPQPJYEliPGCATx61_dJkVGnZpqokB7XKFB3UFV5FAHRzwzkSXDJIO2tTnS0tQIBxAGbMjtiCPw0D274H69IxrLXD-dvU9QVcflBzqg_pgJCZ6_ziv-6I_u2M1MV2KI3doKcnlHzdXVCCc30pCjRiD1LxkpswDXJz5b0XsvDyJ8OfuozGudXIsSgD30xXWd7qUps3ZsaMBh6cu0S6P8C4n5hRAuF4roqdfO03ZOulEeJg6qofJvIStleH1_heP4TQEZgCxZgdCHD__KKGDLE_UArbqM5cqv3CNTmVuXty9TRjMCmTiFIp8yT1qRBIpdOJlGD8EaOSGGncjCSbmT2AfLZphPBhC0E9zzpwZq7BWQEIrCFhfhO9lkasKwtWqxAo3lEMiL69qG0kb5iXtE2SrFUx8bopcvrmZhTqoOtp-58U2CGrz-1gLsC81WEsQK3gz1BSS8YUGnBwYDq7d8631yV2Uc3ma7eGyKgZouicdwRzDFJ4eVNxKUVntXdYBQduTh9i0gLQYiJHF9GSacLAHUp7RnwOOcgTegjvNjvBKdaVFdywfEJJSTs4a7FTq7gBH96Gb0sguvP1GuSTytgXlH_NxofQE1I3diutUc92kC9cM9V1pIhCN-q5R17CpLHLDoFkYAWXSC8iTdhUEChKZ2LPbqmp36HXUaK9yFpVjThC3AlrRzrhoNq7ufAVQ3oVO8tNw-InMXwGG0G650mvPLy8V2ZcLF0g7dpCjJTSBG2jMF7e6RwfLOjRtlAK8maBHYN6yJYea2dEalEnTC75opM0QX9vSTiwD59wdDyT3KKf-chO4efd2H07ZyaSuwfecAYjzKHrm25Zl24Vq3f-so1XWRB2aunzAKCPcUPIpCsjJ7pA7SVMI3QNzrFM5oJZLB2WiEPiIH90_MLtlzjr_cEodwZ2TLNz06z9JAw8XpzM-cD4D8RrDjySu75yV2B05wSinOWh6S8UbuDeV7C1s5xyYpWXV4AaU4Ak8M9PNacYqB5lIcEfyYcKUoRUoWcHc9JfBCirhm4MgjazGQGoYid2xmWLfiJBjeUDGEB4Df_z7EEaYwiFqxUM7ZeViR4iZk5Ov0_1hVCuUDr_uPVxsbIj9gqLu82yBLVFVXdowocq-3CTM2OlZleoPYGi63Cg8WUXqw3fH0JjdfmczU8Qc2Rq20AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIDxMcHygvNA",
                "userHandle": "d2ViYXV0aG5pby1tbC1kc2EtODc",
            },
            "type": "public-key",
            "clientExtensionResults": {},
        }
        challenge = base64url_to_bytes(
            "nABNh-SsdlomIGuUsRvWFa5dBGeSgfINcp_McGS1yIWIYf4UtV5lDL6yESx9jZ5lYkjro0YS2DdxzF9X7kIyQQ"
        )
        expected_rp_id = "webauthn.io"
        expected_origin = "https://webauthn.io"
        credential_public_key = base64url_to_bytes(
            "owEHAzgxIFkKIPB266vR3jhFEvswhiiULf6og2993LKO8euC16EFiq3z9bud2jKbB6Zw5xm7vOQUIZyCsN18qxjPRoI142swvpDA4rApAGZb028Qgyrz4eQTfueiBsy-GRJ5IN2rsVlFcz3enbYWgh_UWQDSMA9wNfTPJZPz6T-z8KTz60szO8Mn4UG1kLQ5YSV47b6LqJVnrsWzTFe0nylAkpHMtBHS3UNjhoEYNc6HyL9ehBoLGs3Z0IPusTYdcZ8LA4icQsoX3X8XEORW4MV5x1l9qwC_6-iZ4rAsbSUsUMDyB_h-FKn7TP9X8x_IA6fCDuUIL2vMWwVj-yNtVbw_NqJkm5OePjPQzh04F6wxLd4y0qeLZA7ycjADjACLKa_IJVFMgxx_7nJ2pbHKOYfqJzAnCg9nqMUVeonWBunJatFABgwKR4-cNzV6pcn1bL4haHbHdblbZ7f0nv7-DPz75BaZhDaurOBLBHGDh5bC856v0EkPOfRO81pKBa-EyT3OkZ7qejOMeEZpbvhCvECisLwbKo8lcAR0gaqHLNGEXcqNUFXVbLzdfcrDd_FMD-kBByAlGdMswYANrFpLVpmkJEGQ_Eqow99ZcyBvdwxtxCQT3X4i3rFRhB8FGP9JAkODC67U-EWIMyWF2VIseVZkxMngwsZAm327jFIoOfupWeUGjpGORhOvI6OPA2VzR6wrFjkfsM_6bt8VMHIpo5lUtGMKND5K2M3fRCFvQqPWW7MOQ83b-6qfa-GcGKzVfojGd6uwVJjgDDJldMMve8OCTktiwIJ4h-n5ObGRvlJQ7etgycCwXINUkb1KFZovgUQnujhjK4f0M0Ib76scKCmYX_UtexSCf09jkwQRgtBh3BnzJrgILfErMmfK2Z1z5wWUV4MX2oXcNkWyGGH1kCLnzXu1qveFsry7Hf27DyceNIAzuqkrtcsJgw7ePhXHz0AgdYo8qyQmXSPfhAEWiwtCZ5MbUKmxn-8pGiRKqUtbzpYTNwTpj2PdpzK1zvAAHubIxi5XXi_JEJL8h2HOmkRJLLo26GDfNV0n0SRGhujW65LNdAU7ggrgzEcdbkRPNX0vsyax0ZBr9HXs-GnlR_4ySugcgGVIdj5xv7xsvDnfy-bVPMLgOP1nCLvZROJwMAA3XOAD9SKjsQMLKQjsiZHIelWzOxHrr360wowj3jclxQUD9XgDtNfff6MjiS3rsBO05ECyF3bMcsjsRak7GStJ2MFBAbdESryKek1z-2g4ahqUuO0LGeX7Klzi110XpqN9VYrrvUNP6seqm_V48PinvDDPsfsHqC2ZFPRtWv3rcZt6RbA9KLsqXqWphMqr3MZm8k69E2ZiWn-wFHXMBWTKzrRxtiBOHk4mcygTOIn2AsjVMO8GCglyJlUluN0eQWiapr48lnE3EetPNGxq86wn28wPQhC56jcLkNHq-RDEjycvFzUzgoa4i1mJCW038vHGPH8-CLYGggPeSOnL-zZMRtw-jDaMR5HHc95FlsTLlMVbpnb-eCGT2-khduVx4HdpdoTJHfT4PNQTTVnVY6N5vUP9x5jXq6p7Zwvl_VpWR9jxZZcO1KIoi5ozIgE5XqNF-NKumoouAfpZWxauhdkBgUL86WnH3zQah8hHY1d7QeZGcfo4fx8S0NiTsVa9wIat3BBlck3HmwbduMP7Web7Rhf_Pj3lfhVrZ0p5nKFizbacQcK4mVwCM8MPaFEN6xAIwqLzFYWIwc_sUKxRq2WLg3RvIbBl0-TesJfzSPWMJGcq4iropcn-JW8XFQVJyf4KBFuwImpXq1wrOalOjIgAk5nGiYxLxK3feeOoG22uBNkfg_qJfqzGX_o3BMaXZyvydAQCY36z2SbFEme3LxsdC-vYUi6iVuxVdpL2gXm3OtNiI4iGvBNoJvGzHZwSh0-GpZbqdN_wZMFimvz8R75O2PPXSkmyLyDmNxDaSGsnZeQ4BCyD63YLnhFlWzG7VBIdAr570KEz9dhU6ozJ6iP_mtETAImGWB733xuIeZ2D3Aj-Q9l2s2xfPKqPXkvOe2OjC288A86T5l5_9mANfFgfLCjdsMwSQau_EOkrvmPkaHacBoWPfPMWwyBJSnF6jNPHoaRBtFba6Ld-f4ThJyaza52JLza1xIviFn37XzFCvLRXrpI6wghURUP2vk-dMs1l8hQRH3RIvcBIqctikAL3NuY8otXhQUw-1QjkIv2llYeXARAhE-2bIvATrf7FrVN4hJBbU3uesAyYvpG9NN8XGztoptOotFP_pYH67yUaiYJXmnPTzWEzk0F5kUhZTvy7ZlwKMv2EINrXDc0q1Dx0MJnJSe02PQr2C0RzR0zkTi00-y104KimThbs7QLRgnke7BlaJtgJH7T-KETvLqs6Ogpptzntt6whM8lesXUvQr5jm3l0WLCSo1W8-q-Vxfo8v6cbkHxsP_xoM43uOsklCuypxyVfnBRVGsgL9W5_7TaZTWMdfoak9fwMjd8j1lu6oXmOiu96TQ8vpETLuN4A1AOnFS1grl1dBZ-kUoKV_vu4ZFDkacK20S8Q5X-WcM5zKmpVUWL3oyWg3VNxSDu_16LLPQ7pYfgS9dNftCHnOjYUgY2Co_xD0ejB83G-a3aC-OSBwo7NtOHTfh6gysbSzBwsJ0Tw9GyCRRLqpu4YsWGkJXiblfGI-2zH8aGm0GZLz84p8FqRCipTbMt8yjFjKDoCp3iBpUTfMs3uON28otSpkgF5XPIwihK7O0Fu8tw-DMLXbbxMDxyAhto3xGb7Q1KT_-hc4SrghI4dy_Evm095K6Fr3sHsQ_oVck2xd71r4e_uPCXFpiHbvImwtuE94XyGgy9y1l2TvRa6P1ZpKh-ccxv_v1TZdf3gIn04M7kio46WfIiURcS6aoVfCef1pUpGRcVgxnwWrJw_8tu7MZUukXmM3SA7dezKIe446WE6BiXay7TNBu9yThxldO7ooK6udljaap3pEyejRWNJ83zSVv5OwjlvDtC4joCHJ6BejJh60OM0KeiMniTJftrV4F3ZRMgn7MdbJtUYOY4SoodNAfPEBr5n_6n7ZCT4uBAsLtyYwHmzjIR1qZxOVfH98C2xOrp6ZWFMiAlrJkPDoiD8sMMB6oWA2aT_vPcixKBQqNqrkeKScusIiThNCTrlK5AkDe_AqUEW1qu8E6Qbb-7YLCrhqIbMmg5eGKXZ7c9j94jd-rShqUz2seWaLAXkKi-VMsUdTnlgvQ-A_6IRd8wM30BpVQeDuS-AE3cfnw8poVsuaPsMU5me9Ro1um1GUEU8mLzSw6ZMgHlbFapubropKvU-2-s0nozxQzs7bh4NkPF5gZ1zuf7xNXcPV3uodzJnmtBNn7lcfJK69serkxLEKOa7IiS2osGQlxDh9mwwMip7fuVPhN9ZWadhWnrFlWfdKzv082WxErNeM_SslKaeg8UJPzRYllQ1szvS3pYyt8u3JSX2zw"
        )
        sign_count = 3

        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=expected_rp_id,
            expected_origin=expected_origin,
            credential_public_key=credential_public_key,
            credential_current_sign_count=sign_count,
        )

        self.assertEqual(verification.new_sign_count, 4)
