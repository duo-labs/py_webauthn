from webauthn import (
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers import mldsa
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

################
#
# Examples of using webauthn for authentication ceremonies
#
# Authentication responses are representative of WebAuthn credential responses
# as they would be encoded for transmission from the browser to the RP as JSON. This
# primarily means byte arrays are encoded as Base64URL on the client.
#
################

# Simple Options
simple_authentication_options = generate_authentication_options(rp_id="example.com")

print("\n[Authentication Options - Simple]")
print(options_to_json(simple_authentication_options))

# Complex Options
complex_authentication_options = generate_authentication_options(
    rp_id="example.com",
    challenge=b"1234567890",
    timeout=12000,
    allow_credentials=[PublicKeyCredentialDescriptor(id=b"1234567890")],
    user_verification=UserVerificationRequirement.REQUIRED,
)

print("\n[Authentication Options - Complex]")
print(options_to_json(complex_authentication_options))

# Authentication Response Verification
authentication_verification = verify_authentication_response(
    # Demonstrating the ability to handle a stringified JSON version of the WebAuthn response
    credential="""{
        "id": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
        "rawId": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
        "response": {
            "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaVBtQWkxUHAxWEw2b0FncTNQV1p0WlBuWmExekZVRG9HYmFRMF9LdlZHMWxGMnMzUnRfM280dVN6Y2N5MHRtY1RJcFRUVDRCVTFULUk0bWFhdm5kalEiLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
            "signature": "iOHKX3erU5_OYP_r_9HLZ-CexCE4bQRrxM8WmuoKTDdhAnZSeTP0sjECjvjfeS8MJzN1ArmvV0H0C3yy_FdRFfcpUPZzdZ7bBcmPh1XPdxRwY747OrIzcTLTFQUPdn1U-izCZtP_78VGw9pCpdMsv4CUzZdJbEcRtQuRS03qUjqDaovoJhOqEBmxJn9Wu8tBi_Qx7A33RbYjlfyLm_EDqimzDZhyietyop6XUcpKarKqVH0M6mMrM5zTjp8xf3W7odFCadXEJg-ERZqFM0-9Uup6kJNLbr6C5J4NDYmSm3HCSA6lp2iEiMPKU8Ii7QZ61kybXLxsX4w4Dm3fOLjmDw",
            "userHandle": "T1RWa1l6VXdPRFV0WW1NNVlTMDBOVEkxTFRnd056Z3RabVZpWVdZNFpEVm1ZMk5p"
        },
        "type": "public-key",
        "authenticatorAttachment": "cross-platform",
        "clientExtensionResults": {}
    }""",
    expected_challenge=base64url_to_bytes(
        "iPmAi1Pp1XL6oAgq3PWZtZPnZa1zFUDoGbaQ0_KvVG1lF2s3Rt_3o4uSzccy0tmcTIpTTT4BU1T-I4maavndjQ"
    ),
    expected_rp_id="localhost",
    expected_origin="http://localhost:5000",
    credential_public_key=base64url_to_bytes(
        "pAEDAzkBACBZAQDfV20epzvQP-HtcdDpX-cGzdOxy73WQEvsU7Dnr9UWJophEfpngouvgnRLXaEUn_d8HGkp_HIx8rrpkx4BVs6X_B6ZjhLlezjIdJbLbVeb92BaEsmNn1HW2N9Xj2QM8cH-yx28_vCjf82ahQ9gyAr552Bn96G22n8jqFRQKdVpO-f-bvpvaP3IQ9F5LCX7CUaxptgbog1SFO6FI6ob5SlVVB00lVXsaYg8cIDZxCkkENkGiFPgwEaZ7995SCbiyCpUJbMqToLMgojPkAhWeyktu7TlK6UBWdJMHc3FPAIs0lH_2_2hKS-mGI1uZAFVAfW1X-mzKL0czUm2P1UlUox7IUMBAAE"
    ),
    credential_current_sign_count=0,
    require_user_verification=True,
)
print("\n[Authentication Verification]")
print(authentication_verification)
assert authentication_verification.new_sign_count == 1

if mldsa.is_ml_dsa_available():

    mldsa_authentication_options = generate_authentication_options(
        rp_id="localhost",
        challenge=base64url_to_bytes('Ju9EKShZeDU3M3cD6xE5eYUJgQ05Wc6XObqkdEvTGuI'),
        allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes('ZAm5To5dRDuoBHlOoo5Fl19jcnlwdGFuZQ'))],
    )


    print("\n[Authentication Options - ML-DSA]")
    print(options_to_json(mldsa_authentication_options))

    authentication_verification = verify_authentication_response(
        credential="""
            {"type": "public-key", 
            "id": "ZAm5To5dRDuoBHlOoo5Fl19jcnlwdGFuZQ", 
            "rawId": "ZAm5To5dRDuoBHlOoo5Fl19jcnlwdGFuZQ", 
            "authenticatorAttachment": "cross-platform", 
            "response": {
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiSnU5RUtTaFplRFUzTTNjRDZ4RTVlWVVKZ1EwNVdjNlhPYnFrZEV2VEd1SSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZSwib3RoZXJfa2V5c19jYW5fYmVfYWRkZWRfaGVyZSI6ImRvIG5vdCBjb21wYXJlIGNsaWVudERhdGFKU09OIGFnYWluc3QgYSB0ZW1wbGF0ZS4gU2VlIGh0dHBzOi8vZ29vLmdsL3lhYlBleCJ9", 
                "authenticatorData": "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA", 
                "signature": "UrG-HahybZhDjwuvU8gmu6ne4mSwwKtzYYe_miIfoWE7BudVZO_BcvsIm7fttJldSIdHR6hQVCl4hz-zoweL5g1o85Mm1008NsfhIF5mF5Bx9Q-8YvsooVRmc6mSAnWYhRubLxvtw68vTN2u6ncP7YnkuTc7Q-ui7FQ0K7uYa3L3huDPyb6fqZAgVYXe65bzSIrNICdVdFKEmUb2vph65aV-1SGiPY0wEQxi86CRGpYoOllVCffUYqkUDpUb2O-9Axqw-Unnqx_UTaukFHzD2NGFiNWCMlJPWYReNjmp4epAEEkmxwuSNaXmLO3T8lZ5uLFS-5bc0t-kHAyD_doINTLV-FyEIBC-kX74qmTSKAN41YIl0t7-k2i73Y2HDBdbHY28gWxIb2pSA1mfg9z17EtfRSjmlRGpK2M03tnUOl6Un8U2TE5j9KZSKXlVvCAqLXr93v1OEtJbSoF0NBG4TH_6xySgzPlKck2kRGwhwj6DCiOt1zVusXLeu_q_Fh3mLQkdvd2j__UyvhnbctD_lwU7A5j9h9G6uVsQQ_w873nPJvriqqL-V9gHPFvuRTcL5rENgyfnPwZ_YDCc9ss90jd1ow9zPQDT7rsF9Xm9qLZrnV3JnH6a-IsIXBy_yCOn9Zpcn3hm2kPbCqyx2_pcIyH2msV7q5i1WXs4vkur0J-S5fPC3tDm5RMz_Fs_JiPmE1TjW1H5ZB8TrYqiFlbls1cuow5xJmw2vrHWPvsWFVV-JYI_lbtuO5J_spClzRdGcroUetGfSBcc49PIDEOVO2dJ7xeFtpqentIDuM7mtsTaJRKqxCI07TdJ799i9lGObX6XAsiWns4XaBjF48yxW8DCXb4HyEPx1eleHIigtLH05Po-Hunrxw5SW8a9d-H78F-e5PVKf3lyb38YUwx8_nWhaTGn9wV5-Fay-pefwz9su5S4MKF97th6VMEc2eHZirHw01oTnUxddvTma6L0jkdrZBgy08FmVfUgs57pmHEJURsP-3351WcKoyV8a27EJvsTjL88uzUgo2zkho7H1vdKWD6VOGZsTSX6HqvtSwqbcKN0YVGUxp7LXw4Qf5M9DgX4l1XW2LXKVCQgxiVFvnVmRiOdYXFkDWMIfQ3hiwna6YNiizi_hZVMtsABoqkxfuPlJ6aspeCulE7vyA4UykbMQ_fPFDD2zpsQWOlIAKiZ6_hB4csIX6v-USeSKQYiTxPQfsgUNd8TJUhdECzaNYTG-96T-INqibJt7mlkZJtUC8OCnFu5UG8Tr_i8dTXl-6AsFk_-AkvunG9vN4U9qLR1C-XMGduNyuQHuohc2FQp1fJ2o9H3FrbQ_WTl1GOQ1KZU6BFXUmzukD-g1-UthKZlteSybOjzRshRNqQzklgB5tq6xHBVTqdQKJcgSYByQI0QjLGPWEj8N2A7zkTdpoKNu76QaQSnMidBOF2WO3KEkj6PrkUHMIEFcBvxbhV0jJ7LRYD3bH_dgIk7e7wOAqda5pRYYSsrzDsWG9FIGzS_XRb32dpC9bH0cdwimA3MfVA8B8OL1oecyJ2LS8gkWn_In_U1LGdhWdeeiyMrih-JAhnvjtPIWJB4lZyytRTZ_kzQmCVEjAAuaLo7NsYtSuF1qsVuMR4FEs-Y16XkC3zIk7UjNnril2-x0VBTz0ZBQHzYBgv56aQwLRVshUDPLqCposFI65QCkE9ChfoSMH4AKU3AMg5mnq1tP2wjDhgddbUVGzJQ6Lpj6Jw4Tc-tEhGjJcnfz_4JO2I2ZM6wnG1OjhE7BZsONXAck1WTngsiptLPtbSWTh0EFoodYHQbqNByb9sTmE7HPzuRR9YzkifQ-AWDltE3_ij34BRjbJR1x43PC1L8tVDXvE6baxhA9uWKGVfQo-g9XLUnhFDFRIWRPIW6SLLpraly4UdhfPyC3izXjW2niSnBFyYsabxmV0P-lYgU4HhGPedVDgw4UkTwu4bMij4lavMcRJhBf2i6RP6vJi9DYF_WB4Iq1QlBOlwFud_urCiJFJOfLhBWAdNjdQFzgAp-oPVBcyhxU7LtPJJC_djAbTDdfXJ7PWZQV-RxHoWz1dIUYQngQaU_eji79LxRrUmzxaeZ3TiBXbnYrd1oDeY1JWylbeldUO-JXJaoCFTrXWE2-K97H3egpoY7KtH6mVPAF0wfiaPqA3BVs6cGuZCKk6rv0MQhQPJMSMpY2tUOZ85IAMKQQZ8yTVMxr96wkg1i29qJCdCNtnBkDCT5LKghDD773mhUcCLgVWcC9kyIEMxhDlC47SIOOiQxe0hIZkHv8WPyYf1OB8Xd86t6Y9IRnCeEzNQvhJgEVREvaQrEhkyNLkA3FfplfAi0tCwWf3zTih6_IMw3Z_V4Vn04WjN8zU_QtDHk4SqCQj8Drfxdhh620V-luceXjyKgYvRPHCIoavJMOFEN-SdqTF8BgYJE0XW5LZNSQ8_qoNYdvGJRGMul94bCd4TZCj1pQi09j5PPhpl7-PWS8ncMe5aiOld_p3ui4Kqrd2s_nV8hkbkzoTxte8WTz7Izj6Dj1LofXH1wl1fVn0EGg-yIZUVPrScTGhvBSKUEQ2vzszTJC_LISVBZQLgGExtTAp_Nrnsre0sMwZ5uGT1Ys6dkIUxXywlOU1T-c2ZlP4U-i8-frpso_X6ZctL9eUDl5c2SdTo4kz_ePy0TvxLSPf3t8koirqdbUlmu0Ni7b3ys4Q6cHPs6F4Sj-EK4UhGN7_hrgxrSeRUuu1w7boFaNE3AsVeLOdExnz_D3SHMe8jvMpgaV8YnvJNhPIz7DqjOtt_2iyYGs7nkAjchK70i4oDAkoVVK2n4YWiAPfTYDOYOc4qHR8wJpFb1cEzfl9lXlZ5jh1sai72oF6GiFsWgmXJasNnRPKVM6kXMaQL-UFS1rDTjg7JKj1gEY2OZabbWPa9PZWWQG7ACik2ywvQd8s38HBZKcm2uCIfAPsQxlFnHhrcPkcECqycsjqmalqOBz52EFnDaHFywN6qIEob2daUnk82Rmznpmied8YNEBOL2YiPXlFwYlaANUHnMtX7m8bAbmMSf2DqeJL5sUaq3sO2gOhrxpab49cZVem0xqKRkaXBlgwXuKJIYB6F2XesbEL4NGyAlQklvd5WgqLK6vcvj5AIdUV9jaZWYtNbj6fsZMzVEXV9qbYrDy87q7fH9FidQYICSqLK2z-QAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABEeLjk", 
                "userHandle": "dXNlcl9pZDE"
                },
                "clientExtensionResults": {}
                }
                """,
    expected_challenge=base64url_to_bytes('Ju9EKShZeDU3M3cD6xE5eYUJgQ05Wc6XObqkdEvTGuI'),
    expected_rp_id="localhost",
    expected_origin="http://localhost:5000",
    credential_public_key=base64url_to_bytes(
        'owEHAzgvIFkFIDLv2uj40pdNSHikjB3u40Kqbu-yl3EElOFx5eOiTYd9wvFrn4Fu-sGZEAfdeyfaP-kn9kutMB4Emov24SLWS4gf4DISj4hJ_UyUVfUpGD8TeOQbRnLgBGaucovj5C2meAHpsVGTrfWzSYydon_wyr2VTJOZKQVRtKmHo5sAmxxhVHqfwojh92Snh3OQst59gRlYu3uzd2shddHU-eWuSoRhPlrEW0qJ3dsZKGBcEYP4O_oBWHMTzo0l0n1SrU1SFMo4IYsC9DGmy70J38mB_FmNkxqfgXvk2WT0SiMx8Il3ypBNM0OaDIG3LAT5bHHYI314teO92rWOYZ3R2NGBmNjrTAOzFYzFyzLN4zpWS394r0vLMVI7qVc7sHqWbTzvT1A9o2uCO-MK7MV8W1YdMUl8SuTQF3nkYAiojqfj17d1a6pOQP3KJPLsFNK6Zc1IyJ9TI6A9kEfES3sTh7xe9clZtj5hpeLikQK_s-sbzQQGI2u2b9tuWkSwNXu61p4Ri9CrV0qhgmH5PeqyH7HYtvF4az1Ld0VN2iSQCIYN9DJGhsepns5gOJKco_HmO4lOGBkPeqNyrPOrYb62X6xRw2k_kh5AwIyCzNj6m47peyFoM7EEurmFNblAn0bxDblevADf22Yoncswfx4jBEikoqOUk1uUXWimLyY0MKNBmWgFfs41d7QGZzSMag1UyCIKNR7FUwgUgwZMnnttPMHNnp5kJlgmL6GoqOSKcJV_F-h4b5j7SVAcXXCtdTWxWSv8iS4gBi-gk6MrqfA8gq7Wtth77eejdAMEHTYlhXzWPfOTdPGAJTLCgUeGJYbM9sFcuIwIP0vMZyw77Dl1JCGRRSzVRr3bKPPX83_k3gkOTC6Pp5gyvQOB3-nYWhs57ksvswL98YrbxiMZTw-e4M2H-1Y-0Hrkitq9o2VN2fnrMOTkv9x94BO_t94WegHzQtjREnnLYTLTPWKHg9IinD4VIxSVxeLEH6H8fGueIPxGFhx5k49d1aQElsHPD_BCCe8K7HGwZxAttW-t2vNH2mcTK8AHoajwq92ST6TSxNzjVpWjIQUHZKR32R7FUcnJmGy1ptE5n8GbEkKhktlnJ7VJrHHsjHsNgLMMoDFNAJqFmM06TcSmiOuPcTMHFjlpiEpGNkRAEPsmp7o07lmUbi9CXidxZmuOPRIo9WyAdqmyjvuNrkaXCo9D7vWpMJFYG9T2GmNiEygohTVBMOYK6KmXS_FarFRxOPVLKVAKcA3NOoToOH5vVzq6W9yT3ny0IXl6EWJhqYbwC6y7hNugvpi2rElyU1cuA3Mv-cIa3zRbV-y1iBQSDxU31Jem-4xRRzB0xf3Od1dLnwUKLRoC6V2ucYkQr6B05aZMu_eOlm6JD3oualGmIii421Iu3_8hvXTVgtUMWMuZiXHhkIxGfNpZXx-KjJluPkfPeHIdHL5efXKC8Oc_ajbcRCS0A6yubU3VjcPqTFvCgfzeMfsaxgblsl5nCeHiOnT6Gffd1HIGNWkKeBsjH79pHFJu2IisreooQuOKkUWQUW8rx7Vfju2CFyvldvT14IQRf8YFhE0lvcc0cl1HTgQc-jwiswjTedz5bK569SZzDTYlREJhj0x7fiR-eaCME4aYbR0OMK3MGF7rp7zH0Oa1pBacnRRKamIFZXsdVHWk8pTjaNSFJInXb8foT4DFcvQ4x8EU_nMIHj3UnHCMfTmNNNztocfnWMSw4CbaEzJPb9H4vLYkAZ3BXNM='
    ),
    credential_current_sign_count=0,
    )

    print("\n[Authentication Verification]")
    print(authentication_verification)
    assert authentication_verification.user_verified

else:
    print("ML-DSA Test skipped. OQS not installed.")