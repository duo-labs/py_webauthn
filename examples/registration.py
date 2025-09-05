from webauthn import (
    generate_registration_options,
    verify_registration_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers import mldsa
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialHint,
    ResidentKeyRequirement,
)

################
#
# Examples of using webauthn for registration ceremonies
#
################

# Simple Options
simple_registration_options = generate_registration_options(
    rp_id="example.com",
    rp_name="Example Co",
    user_name="bob",
)

print("\n[Registration Options - Simple]")
print(options_to_json(simple_registration_options))

# Complex Options
complex_registration_options = generate_registration_options(
    rp_id="example.com",
    rp_name="Example Co",
    user_id=bytes([1, 2, 3, 4]),
    user_name="lee",
    user_display_name="Lee",
    attestation=AttestationConveyancePreference.DIRECT,
    authenticator_selection=AuthenticatorSelectionCriteria(
        authenticator_attachment=AuthenticatorAttachment.PLATFORM,
        resident_key=ResidentKeyRequirement.REQUIRED,
    ),
    challenge=bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]),
    exclude_credentials=[
        PublicKeyCredentialDescriptor(id=b"1234567890"),
    ],
    supported_pub_key_algs=[COSEAlgorithmIdentifier.ECDSA_SHA_512],
    timeout=12000,
    hints=[PublicKeyCredentialHint.CLIENT_DEVICE],
)

print("\n[Registration Options - Complex]")
print(options_to_json(complex_registration_options))

# Registration Response Verification
registration_verification = verify_registration_response(
    # Demonstrating the ability to handle a plain dict version of the WebAuthn response
    credential={
        "id": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
        "rawId": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
        "response": {
            "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ0mWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRQAAAAAAAAAAAAAAAAAAAAAAAAAAACBmggo_UlC8p2tiPVtNQ8nZ5NSxst4WS_5fnElA2viTq6QBAwM5AQAgWQEA31dtHqc70D_h7XHQ6V_nBs3Tscu91kBL7FOw56_VFiaKYRH6Z4KLr4J0S12hFJ_3fBxpKfxyMfK66ZMeAVbOl_wemY4S5Xs4yHSWy21Xm_dgWhLJjZ9R1tjfV49kDPHB_ssdvP7wo3_NmoUPYMgK-edgZ_ehttp_I6hUUCnVaTvn_m76b2j9yEPReSwl-wlGsabYG6INUhTuhSOqG-UpVVQdNJVV7GmIPHCA2cQpJBDZBohT4MBGme_feUgm4sgqVCWzKk6CzIKIz5AIVnspLbu05SulAVnSTB3NxTwCLNJR_9v9oSkvphiNbmQBVQH1tV_psyi9HM1Jtj9VJVKMeyFDAQAB",
            "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQ2VUV29nbWcwY2NodWlZdUZydjhEWFhkTVpTSVFSVlpKT2dhX3hheVZWRWNCajBDdzN5NzN5aEQ0RmtHU2UtUnJQNmhQSkpBSW0zTFZpZW40aFhFTGciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
            "transports": ["internal"],
        },
        "type": "public-key",
        "clientExtensionResults": {},
        "authenticatorAttachment": "platform",
    },
    expected_challenge=base64url_to_bytes(
        "CeTWogmg0cchuiYuFrv8DXXdMZSIQRVZJOga_xayVVEcBj0Cw3y73yhD4FkGSe-RrP6hPJJAIm3LVien4hXELg"
    ),
    expected_origin="http://localhost:5000",
    expected_rp_id="localhost",
    require_user_verification=True,
)

print("\n[Registration Verification - None]")
print(registration_verification)
assert registration_verification.credential_id == base64url_to_bytes(
    "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s"
)

if mldsa.is_ml_dsa_available():

    mldsa_reg_options= generate_registration_options(
        rp_id='localhost',
        rp_name='Demo server',
        user_id=base64url_to_bytes('dXNlcl9pZDE'),
        user_name='a_user',
        user_display_name='A. User',
        authenticator_selection=AuthenticatorSelectionCriteria(
        authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
        resident_key=ResidentKeyRequirement.DISCOURAGED,
    ),
    challenge=base64url_to_bytes('A0uDyVNCuBOonk-L5Vd0qVkC9tq72_Rk6KOdpAxx_NY'),
    supported_pub_key_algs=[COSEAlgorithmIdentifier.ML_DSA_44, COSEAlgorithmIdentifier.ML_DSA_65, COSEAlgorithmIdentifier.ECDSA_SHA_256],
    )

    print("\n[Registration Options - ML-DSA]")
    print(options_to_json(mldsa_reg_options))

    registration_verification = verify_registration_response(
        credential={
            'type': 'public-key', 
            'id': 'ZAm5To5dRDuoBHlOoo5Fl19jcnlwdGFuZQ', 
            'rawId': 'ZAm5To5dRDuoBHlOoo5Fl19jcnlwdGFuZQ', 
            'authenticatorAttachment': 'cross-platform', 
            'response': {
                'clientDataJSON': 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQTB1RHlWTkN1Qk9vbmstTDVWZDBxVmtDOXRxNzJfUms2S09kcEF4eF9OWSIsIm9yaWdpbiI6Imh0dHA6Ly9sb2NhbGhvc3Q6NTAwMCIsImNyb3NzT3JpZ2luIjpmYWxzZX0', 
                'attestationObject': 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkFekmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRQAAAAAAAAAAAAAAAAAAAAAAAAAAABlkCblOjl1EO6gEeU6ijkWXX2NyeXB0YW5lowEHAzgvIFkFILCau9eCTbGwd15c9JemK6obEtvxDREnBm_KMEPyiKpO8Z-MmvkhJzLO62SOHHPLxnLcsgpQ_rmCY-Yb2VKDfREPyZdXAoVEkBYfvVReEac6cPI3rpfLyJRCpTNhaTziAjfmvgAKiO62I-d6cvGYkp-LZhuW-qBIkYOUxf-Flg3aWKNGYGIymVtNnG7wa0NeUXYnuPWsbYAsjwFvbKtJcmJX9sx1WPmI79u_m73hPK2XWGogFa6ngTG0KETf9lIruZBsZLSOi4YWkRLYZ9JISTziZeze3eknIUSssJ-JvU7GyB0YwhXfNfcC4tDl9AAST451_OjFvRY_xIs1LSKwf6t6nsaZQjKJGo6lMDO78WofyEQecAs7yv7DIWdB2oUt9ysT_w1Q5OfYDTuA0k1JxrE74yq6JFEZ6oLFeWczQNjJpnQ3UKIYat454XEZsxF47_fBuwV4HuiRj9lRJhOxCiDTkZ874VtItD2ESgCf9ADrfNyzDWXWuU8SuJ_xc292N1iTeBK3XkoGHDzyaCF-hQPLsW2LBL8bfa8z8V0kfpjvqkJmR1N4aEAyYDiW_L_AA4pZ8tUqWWnMXL9YtfU2osuUjMm-nnNdgvl_ScR5gVeuzj_Et1srG1iGisPi-zGxOtoOex2_hZ1UvXIsP_5szIMGgJoVgok-hNgJLj0jJ9QP9txIfv0zhpiRGiZy1UyZ7NBNMYcWevmif1RESqulcAh6GEvgdaS0nROZUsB-_qT8W4CaJA89DfbdqJEiw2CntCJEnbR6ZpOHYSEFWJVMIz4i1pHsnipFLIMxfpi9afSzO8RqPqXnkYghFQO33IuywxUhVQlxWlH_13Y58leHKqAYFW1TJ6JtY8b-8D5Yb4b46gOwEQpA8iFDgeFMSj8MHEr31OUchoG4skw0uGQ2PSfZQGn_EjdNaRaJeNz4C8Rz8EhPvkQ7MR2s40dKcE6_Sn_YciSA9XWHYpnGlDlNgeZ7WGjQpIjCtX1w33LYYJ26ov1sv7E9qN2ffydEN1S6mysEkS88ogKJQJNYkG8MLeWqAjGgHJAVcMAwTuG3pLu_PPse4ZZ7yphSOjgldoVv6nSD_14VafXPC4-RjgnHKNimIalipUuT3gcT__wjcMAUsa04QNRx-cmijvy6No0ZA5J5YZ3SOIxpjdkGZ6G1L666aiy8oLdxnzKfEbcm-4j-TybuKgRKCzpf2q1FLB2ddLDYa6mk4cYH0ABggNaL8AT0n72W40RSEF78Tbo33PSsqTD9CXBIJ1lZ9tI513v-A4iw02v7buOXd56p0vnCO75lJhcJfu18G8wGcgPx41ZEEYpzjEkPWO8vlMC_Edx1Tb8pS2Jrx_XOLejBV80dDng9n5EAlxveoWL2dxoozSYgvp47okDRTcm7s4YQLQDuKeCckjl5wOUoFDjBt9-PB26U3RNsc9nlxXu5y6YNcrfK3G2qF92mrMYxaNk-6MOHsWRK_JWD2gG8eiA5QmvvNmUYyUpmCFLiJOnlJBv22ucHHJRyHbslQbwtnGsZZXNQhWrd50m9eBWM_11mys9WnI8Yj669a1wKu7F0ab--nHWpJwGMdZRFkCklL5mm-ZJFSToj8S9BjfUeNwrx8t9NVy-d6RYKU1lFBKxYKP3w24AMLre9O0Yd8QH9YMwM0RNsk21Tzpb-xqqONfRUDpfbbjo9N-9fKZD-Ax0yyWcYHWs5BBc6OosjuYDr1mRa0gJMM4OcnjDFOjfutK2ExLFH13Y', 
                'transports': []
            }, 
            'clientExtensionResults': {}
        },
        expected_challenge=base64url_to_bytes('A0uDyVNCuBOonk-L5Vd0qVkC9tq72_Rk6KOdpAxx_NY'),
        expected_rp_id='localhost',
        expected_origin='http://localhost:5000'
    )

    print("\n[Registration Verification - ML-DSA]")
    print(registration_verification)
    assert registration_verification.credential_id == base64url_to_bytes(
        "ZAm5To5dRDuoBHlOoo5Fl19jcnlwdGFuZQ"
    )
else:
    print("ML-DSA Test skipped. OQS not installed.")