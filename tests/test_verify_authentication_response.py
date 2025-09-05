from unittest import TestCase
import warnings
from webauthn import verify_authentication_response
from webauthn.helpers import base64url_to_bytes, parse_authentication_credential_json, mldsa
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

    def test_verify_authentication_response_with_MLDSA_public_key(self):
        if not mldsa.is_ml_dsa_available():
            warnings.warn('ML-DSA not installed. Test skipped')
            return
        credential = """{
            "id": "ZAm5To5dRDuoBHlOoo5Fl19jcnlwdGFuZQ",
            "rawId": "ZAm5To5dRDuoBHlOoo5Fl19jcnlwdGFuZQ",  
            "response": {
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA", 
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiSnU5RUtTaFplRFUzTTNjRDZ4RTVlWVVKZ1EwNVdjNlhPYnFrZEV2VEd1SSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9", 
                "signature": "UrG-HahybZhDjwuvU8gmu6ne4mSwwKtzYYe_miIfoWE7BudVZO_BcvsIm7fttJldSIdHR6hQVCl4hz-zoweL5g1o85Mm1008NsfhIF5mF5Bx9Q-8YvsooVRmc6mSAnWYhRubLxvtw68vTN2u6ncP7YnkuTc7Q-ui7FQ0K7uYa3L3huDPyb6fqZAgVYXe65bzSIrNICdVdFKEmUb2vph65aV-1SGiPY0wEQxi86CRGpYoOllVCffUYqkUDpUb2O-9Axqw-Unnqx_UTaukFHzD2NGFiNWCMlJPWYReNjmp4epAEEkmxwuSNaXmLO3T8lZ5uLFS-5bc0t-kHAyD_doINTLV-FyEIBC-kX74qmTSKAN41YIl0t7-k2i73Y2HDBdbHY28gWxIb2pSA1mfg9z17EtfRSjmlRGpK2M03tnUOl6Un8U2TE5j9KZSKXlVvCAqLXr93v1OEtJbSoF0NBG4TH_6xySgzPlKck2kRGwhwj6DCiOt1zVusXLeu_q_Fh3mLQkdvd2j__UyvhnbctD_lwU7A5j9h9G6uVsQQ_w873nPJvriqqL-V9gHPFvuRTcL5rENgyfnPwZ_YDCc9ss90jd1ow9zPQDT7rsF9Xm9qLZrnV3JnH6a-IsIXBy_yCOn9Zpcn3hm2kPbCqyx2_pcIyH2msV7q5i1WXs4vkur0J-S5fPC3tDm5RMz_Fs_JiPmE1TjW1H5ZB8TrYqiFlbls1cuow5xJmw2vrHWPvsWFVV-JYI_lbtuO5J_spClzRdGcroUetGfSBcc49PIDEOVO2dJ7xeFtpqentIDuM7mtsTaJRKqxCI07TdJ799i9lGObX6XAsiWns4XaBjF48yxW8DCXb4HyEPx1eleHIigtLH05Po-Hunrxw5SW8a9d-H78F-e5PVKf3lyb38YUwx8_nWhaTGn9wV5-Fay-pefwz9su5S4MKF97th6VMEc2eHZirHw01oTnUxddvTma6L0jkdrZBgy08FmVfUgs57pmHEJURsP-3351WcKoyV8a27EJvsTjL88uzUgo2zkho7H1vdKWD6VOGZsTSX6HqvtSwqbcKN0YVGUxp7LXw4Qf5M9DgX4l1XW2LXKVCQgxiVFvnVmRiOdYXFkDWMIfQ3hiwna6YNiizi_hZVMtsABoqkxfuPlJ6aspeCulE7vyA4UykbMQ_fPFDD2zpsQWOlIAKiZ6_hB4csIX6v-USeSKQYiTxPQfsgUNd8TJUhdECzaNYTG-96T-INqibJt7mlkZJtUC8OCnFu5UG8Tr_i8dTXl-6AsFk_-AkvunG9vN4U9qLR1C-XMGduNyuQHuohc2FQp1fJ2o9H3FrbQ_WTl1GOQ1KZU6BFXUmzukD-g1-UthKZlteSybOjzRshRNqQzklgB5tq6xHBVTqdQKJcgSYByQI0QjLGPWEj8N2A7zkTdpoKNu76QaQSnMidBOF2WO3KEkj6PrkUHMIEFcBvxbhV0jJ7LRYD3bH_dgIk7e7wOAqda5pRYYSsrzDsWG9FIGzS_XRb32dpC9bH0cdwimA3MfVA8B8OL1oecyJ2LS8gkWn_In_U1LGdhWdeeiyMrih-JAhnvjtPIWJB4lZyytRTZ_kzQmCVEjAAuaLo7NsYtSuF1qsVuMR4FEs-Y16XkC3zIk7UjNnril2-x0VBTz0ZBQHzYBgv56aQwLRVshUDPLqCposFI65QCkE9ChfoSMH4AKU3AMg5mnq1tP2wjDhgddbUVGzJQ6Lpj6Jw4Tc-tEhGjJcnfz_4JO2I2ZM6wnG1OjhE7BZsONXAck1WTngsiptLPtbSWTh0EFoodYHQbqNByb9sTmE7HPzuRR9YzkifQ-AWDltE3_ij34BRjbJR1x43PC1L8tVDXvE6baxhA9uWKGVfQo-g9XLUnhFDFRIWRPIW6SLLpraly4UdhfPyC3izXjW2niSnBFyYsabxmV0P-lYgU4HhGPedVDgw4UkTwu4bMij4lavMcRJhBf2i6RP6vJi9DYF_WB4Iq1QlBOlwFud_urCiJFJOfLhBWAdNjdQFzgAp-oPVBcyhxU7LtPJJC_djAbTDdfXJ7PWZQV-RxHoWz1dIUYQngQaU_eji79LxRrUmzxaeZ3TiBXbnYrd1oDeY1JWylbeldUO-JXJaoCFTrXWE2-K97H3egpoY7KtH6mVPAF0wfiaPqA3BVs6cGuZCKk6rv0MQhQPJMSMpY2tUOZ85IAMKQQZ8yTVMxr96wkg1i29qJCdCNtnBkDCT5LKghDD773mhUcCLgVWcC9kyIEMxhDlC47SIOOiQxe0hIZkHv8WPyYf1OB8Xd86t6Y9IRnCeEzNQvhJgEVREvaQrEhkyNLkA3FfplfAi0tCwWf3zTih6_IMw3Z_V4Vn04WjN8zU_QtDHk4SqCQj8Drfxdhh620V-luceXjyKgYvRPHCIoavJMOFEN-SdqTF8BgYJE0XW5LZNSQ8_qoNYdvGJRGMul94bCd4TZCj1pQi09j5PPhpl7-PWS8ncMe5aiOld_p3ui4Kqrd2s_nV8hkbkzoTxte8WTz7Izj6Dj1LofXH1wl1fVn0EGg-yIZUVPrScTGhvBSKUEQ2vzszTJC_LISVBZQLgGExtTAp_Nrnsre0sMwZ5uGT1Ys6dkIUxXywlOU1T-c2ZlP4U-i8-frpso_X6ZctL9eUDl5c2SdTo4kz_ePy0TvxLSPf3t8koirqdbUlmu0Ni7b3ys4Q6cHPs6F4Sj-EK4UhGN7_hrgxrSeRUuu1w7boFaNE3AsVeLOdExnz_D3SHMe8jvMpgaV8YnvJNhPIz7DqjOtt_2iyYGs7nkAjchK70i4oDAkoVVK2n4YWiAPfTYDOYOc4qHR8wJpFb1cEzfl9lXlZ5jh1sai72oF6GiFsWgmXJasNnRPKVM6kXMaQL-UFS1rDTjg7JKj1gEY2OZabbWPa9PZWWQG7ACik2ywvQd8s38HBZKcm2uCIfAPsQxlFnHhrcPkcECqycsjqmalqOBz52EFnDaHFywN6qIEob2daUnk82Rmznpmied8YNEBOL2YiPXlFwYlaANUHnMtX7m8bAbmMSf2DqeJL5sUaq3sO2gOhrxpab49cZVem0xqKRkaXBlgwXuKJIYB6F2XesbEL4NGyAlQklvd5WgqLK6vcvj5AIdUV9jaZWYtNbj6fsZMzVEXV9qbYrDy87q7fH9FidQYICSqLK2z-QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABEeLjk", 
                "userHandle": "dXNlcl9pZDE"
            },
            "type": "public-key", 
            "clientExtensionResults": {}
        }"""
        challenge = base64url_to_bytes(
            "Ju9EKShZeDU3M3cD6xE5eYUJgQ05Wc6XObqkdEvTGuI"
        )
        expected_rp_id = "localhost"
        expected_origin = "http://localhost:5000"
        credential_public_key = base64url_to_bytes(
            "owEHAzgvIFkFIDLv2uj40pdNSHikjB3u40Kqbu-yl3EElOFx5eOiTYd9wvFrn4Fu-sGZEAfdeyfaP-kn9kutMB4Emov24SLWS4gf4DISj4hJ_UyUVfUpGD8TeOQbRnLgBGaucovj5C2meAHpsVGTrfWzSYydon_wyr2VTJOZKQVRtKmHo5sAmxxhVHqfwojh92Snh3OQst59gRlYu3uzd2shddHU-eWuSoRhPlrEW0qJ3dsZKGBcEYP4O_oBWHMTzo0l0n1SrU1SFMo4IYsC9DGmy70J38mB_FmNkxqfgXvk2WT0SiMx8Il3ypBNM0OaDIG3LAT5bHHYI314teO92rWOYZ3R2NGBmNjrTAOzFYzFyzLN4zpWS394r0vLMVI7qVc7sHqWbTzvT1A9o2uCO-MK7MV8W1YdMUl8SuTQF3nkYAiojqfj17d1a6pOQP3KJPLsFNK6Zc1IyJ9TI6A9kEfES3sTh7xe9clZtj5hpeLikQK_s-sbzQQGI2u2b9tuWkSwNXu61p4Ri9CrV0qhgmH5PeqyH7HYtvF4az1Ld0VN2iSQCIYN9DJGhsepns5gOJKco_HmO4lOGBkPeqNyrPOrYb62X6xRw2k_kh5AwIyCzNj6m47peyFoM7EEurmFNblAn0bxDblevADf22Yoncswfx4jBEikoqOUk1uUXWimLyY0MKNBmWgFfs41d7QGZzSMag1UyCIKNR7FUwgUgwZMnnttPMHNnp5kJlgmL6GoqOSKcJV_F-h4b5j7SVAcXXCtdTWxWSv8iS4gBi-gk6MrqfA8gq7Wtth77eejdAMEHTYlhXzWPfOTdPGAJTLCgUeGJYbM9sFcuIwIP0vMZyw77Dl1JCGRRSzVRr3bKPPX83_k3gkOTC6Pp5gyvQOB3-nYWhs57ksvswL98YrbxiMZTw-e4M2H-1Y-0Hrkitq9o2VN2fnrMOTkv9x94BO_t94WegHzQtjREnnLYTLTPWKHg9IinD4VIxSVxeLEH6H8fGueIPxGFhx5k49d1aQElsHPD_BCCe8K7HGwZxAttW-t2vNH2mcTK8AHoajwq92ST6TSxNzjVpWjIQUHZKR32R7FUcnJmGy1ptE5n8GbEkKhktlnJ7VJrHHsjHsNgLMMoDFNAJqFmM06TcSmiOuPcTMHFjlpiEpGNkRAEPsmp7o07lmUbi9CXidxZmuOPRIo9WyAdqmyjvuNrkaXCo9D7vWpMJFYG9T2GmNiEygohTVBMOYK6KmXS_FarFRxOPVLKVAKcA3NOoToOH5vVzq6W9yT3ny0IXl6EWJhqYbwC6y7hNugvpi2rElyU1cuA3Mv-cIa3zRbV-y1iBQSDxU31Jem-4xRRzB0xf3Od1dLnwUKLRoC6V2ucYkQr6B05aZMu_eOlm6JD3oualGmIii421Iu3_8hvXTVgtUMWMuZiXHhkIxGfNpZXx-KjJluPkfPeHIdHL5efXKC8Oc_ajbcRCS0A6yubU3VjcPqTFvCgfzeMfsaxgblsl5nCeHiOnT6Gffd1HIGNWkKeBsjH79pHFJu2IisreooQuOKkUWQUW8rx7Vfju2CFyvldvT14IQRf8YFhE0lvcc0cl1HTgQc-jwiswjTedz5bK569SZzDTYlREJhj0x7fiR-eaCME4aYbR0OMK3MGF7rp7zH0Oa1pBacnRRKamIFZXsdVHWk8pTjaNSFJInXb8foT4DFcvQ4x8EU_nMIHj3UnHCMfTmNNNztocfnWMSw4CbaEzJPb9H4vLYkAZ3BXNM="
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

        assert verification.new_sign_count == 0
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
