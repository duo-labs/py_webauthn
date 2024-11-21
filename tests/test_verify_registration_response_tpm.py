from unittest import TestCase

from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.structs import AttestationFormat
from webauthn import verify_registration_response


class TestVerifyRegistrationResponseTPM(TestCase):
    def test_verify_attestation_surface_pro_4(self) -> None:
        """
        TPM Mfgr: INTC (Intel)
        Mfgr Version: 500.5.0.0
        TPM Version: 2.0
        """
        credential = """{
            "id": "2O_TSbHXS3KJwx5uwajcqbKwWCBeHjOBCXXb7vrPfUU",
            "rawId": "2O_TSbHXS3KJwx5uwajcqbKwWCBeHjOBCXXb7vrPfUU",
            "response": {
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWlhsS2FHSkhZMmxQYVVwSlZYcEpNVTVwU1hOSmJsSTFZME5KTmtscmNGaFdRMG81TG1WNVNuQlpXRkZwVDJwRk1rMXFUWGxPVkd0M1RXcE5jMGx0VmpSalEwazJUVlJaZVUxNlRUTlBWRUY1VFhsM2FXTXpWbWxKYW05cFpGaE9iR050TldoaVYxWnZXbGhLYkVsdU1DNTNhbVZJVWpSNFNuRkdVUzFTVTBabFgxZFVWVjlPUm5odk4zZHRRakJ5Y3pWSE1uRnBSRjluVkRObiIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG50ZXN0LmF6dXJld2Vic2l0ZXMubmV0IiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==",
                "attestationObject": "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"
            },
            "type": "public-key"
        }"""
        challenge = base64url_to_bytes(
            "ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnBZWFFpT2pFMk1qTXlOVGt3TWpNc0ltVjRjQ0k2TVRZeU16TTNPVEF5TXl3aWMzVmlJam9pZFhObGNtNWhiV1ZvWlhKbEluMC53amVIUjR4SnFGUS1SU0ZlX1dUVV9ORnhvN3dtQjByczVHMnFpRF9nVDNn"
        )
        rp_id = "webauthntest.azurewebsites.net"
        expected_origin = "https://webauthntest.azurewebsites.net"

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=expected_origin,
            expected_rp_id=rp_id,
        )

        assert verification.fmt == AttestationFormat.TPM
        assert verification.credential_id == base64url_to_bytes(
            "2O_TSbHXS3KJwx5uwajcqbKwWCBeHjOBCXXb7vrPfUU"
        )

    def test_verify_attestation_dell_xps_13(self) -> None:
        """
        TPM Mfgr: NTC (Nuvoton Technology)
        Mfgr Version: 1.3.2.8
        TPM Version: 2.0
        """
        credential = """{
            "id": "56iW7RC7YLiknnNU70kO5Bb-jip9-WTUbohh_Aqq1q4",
            "rawId": "56iW7RC7YLiknnNU70kO5Bb-jip9-WTUbohh_Aqq1q4",
            "response": {
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWlhsS2FHSkhZMmxQYVVwSlZYcEpNVTVwU1hOSmJsSTFZME5KTmtscmNGaFdRMG81TG1WNVNuQlpXRkZwVDJwRk1rMXFVVEJPYWswMFRWUnJjMGx0VmpSalEwazJUVlJaZVU1RVZUUk5lbWQ0VDFOM2FXTXpWbWxKYW05cFdXMDVhVWx1TUM1UmFIVnJaMWsxZEV3eVpITTRkWGRCY25STFVHRnJTemRFYW5wa1ptMDRPWGx2VTNnMFpsOURWMDlGIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobnRlc3QuYXp1cmV3ZWJzaXRlcy5uZXQiLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                "attestationObject": "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"
            },
            "type": "public-key"
        }"""
        challenge = base64url_to_bytes(
            "ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnBZWFFpT2pFMk1qUTBOak00TVRrc0ltVjRjQ0k2TVRZeU5EVTRNemd4T1N3aWMzVmlJam9pWW05aUluMC5RaHVrZ1k1dEwyZHM4dXdBcnRLUGFrSzdEanpkZm04OXlvU3g0Zl9DV09F"
        )
        rp_id = "webauthntest.azurewebsites.net"
        expected_origin = "https://webauthntest.azurewebsites.net"

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=expected_origin,
            expected_rp_id=rp_id,
        )

        assert verification.fmt == AttestationFormat.TPM
        assert verification.credential_id == base64url_to_bytes(
            "56iW7RC7YLiknnNU70kO5Bb-jip9-WTUbohh_Aqq1q4"
        )

    def test_verify_attestation_lenovo_carbon_x1(self) -> None:
        """
        TPM Mfgr: STM (ST Microelectronics)
        Mfgr Version: 73.8.17568.5511
        TPM Version: 2.0
        """
        credential = """{
            "id": "kU6oEC95fTXAtpI6b2w69fQrKGntFFt1l_2ySjmndYM",
            "rawId": "kU6oEC95fTXAtpI6b2w69fQrKGntFFt1l_2ySjmndYM",
            "response": {
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWlhsS2FHSkhZMmxQYVVwSlZYcEpNVTVwU1hOSmJsSTFZME5KTmtscmNGaFdRMG81TG1WNVNuQlpXRkZwVDJwRk1rMXFVVEJPZWxVd1RYcGpjMGx0VmpSalEwazJUVlJaZVU1RVZUVk9WRkY2VG5sM2FXTXpWbWxKYW05cFkyMDVjMkpIYkhWSmJqQXVjbkJaTTJwVVpVUjBjekE1VFhOSWJUSlZiWGx0WnpsWlpIWnZlbmMyY2xGUGVsRjZNelZpYkhsbU5BIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobnRlc3QuYXp1cmV3ZWJzaXRlcy5uZXQiLCJjcm9zc09yaWdpbiI6ZmFsc2UsIm90aGVyX2tleXNfY2FuX2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgifQ==",
                "attestationObject": "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"
            },
            "type": "public-key"
        }"""
        challenge = base64url_to_bytes(
            "ZXlKaGJHY2lPaUpJVXpJMU5pSXNJblI1Y0NJNklrcFhWQ0o5LmV5SnBZWFFpT2pFMk1qUTBOelUwTXpjc0ltVjRjQ0k2TVRZeU5EVTVOVFF6Tnl3aWMzVmlJam9pY205c2JHbHVJbjAucnBZM2pUZUR0czA5TXNIbTJVbXltZzlZZHZvenc2clFPelF6MzVibHlmNA"
        )
        rp_id = "webauthntest.azurewebsites.net"
        expected_origin = "https://webauthntest.azurewebsites.net"

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=expected_origin,
            expected_rp_id=rp_id,
        )

        assert verification.fmt == AttestationFormat.TPM
        assert verification.credential_id == base64url_to_bytes(
            "kU6oEC95fTXAtpI6b2w69fQrKGntFFt1l_2ySjmndYM"
        )

    def test_verify_tpm_with_ecc_public_area_type(self) -> None:
        credential = """{
            "id": "hsS2ywFz_LWf9-lC35vC9uJTVD3ZCVdweZvESUbjXnQ",
            "rawId": "hsS2ywFz_LWf9-lC35vC9uJTVD3ZCVdweZvESUbjXnQ",
            "response": {
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidXpuOXUwVHgtTEJkdEdnRVJzYmtIUkJqaVV0NWkycnZtMkJCVFpyV3FFbyIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4uaW8iLCJjcm9zc09yaWdpbiI6ZmFsc2V9",
                "attestationObject": "o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQCqAcGoi2IFXCF5xxokjR5yOAwK_11iCOqt8hCkpHE9rW602J3KjhcRQzoFf1UxZvadwmYcHHMxDQDmVuOhH-yW-DfARVT7O3MzlhhzrGTNO_-jhGFsGeEdz0RgNsviDdaVP5lNsV6Pe4bMhgBv1aTkk0zx1T8sxK8B7gKT6x80RIWg89_aYY4gHR4n65SRDp2gOGI2IHDvqTwidyeaAHVPbDrF8iDbQ88O-GH_fheAtFtgjbIq-XQbwVdzQhYdWyL0XVUwGLSSuABuB4seRPkyZCKoOU6VuuQzfWNpH2Nl05ybdXi27HysUexgfPxihB3PbR8LJdi1j04tRg3JvBUvY3ZlcmMyLjBjeDVjglkFuzCCBbcwggOfoAMCAQICEGEZiaSlAkKpqaQOKDYmWPkwDQYJKoZIhvcNAQELBQAwQTE_MD0GA1UEAxM2RVVTLU5UQy1LRVlJRC1FNEE4NjY2RjhGNEM2RDlDMzkzMkE5NDg4NDc3ODBBNjgxMEM0MjEzMB4XDTIyMDExMjIyMTUxOFoXDTI3MDYxMDE4NTQzNlowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKo-7DHdiipZTzfA9fpTaIMVK887zM0nXAVIvU0kmGAsPpTYbf7dn1DAl6BhcDkXs2WrwYP02K8RxXWOF4jf7esMAIkr65zPWqLys8WRNM60d7g9GOADwbN8qrY0hepSsaJwjhswbNJI6L8vJwnnrQ6UWVCm3xHqn8CB2iSWNSUnshgTQTkJ1ZEdToeD51sFXUE0fSxXjyIiSAAD4tCIZkmHFVqchzfqUgiiM_mbbKzUnxEZ6c6r39ccHzbm4Ir-u62repQnVXKTpzFBbJ-Eg15REvw6xuYaGtpItk27AXVcEodfAylf7pgQPfExWkoMZfb8faqbQAj5x29mBJvlzj0CAwEAAaOCAeowggHmMA4GA1UdDwEB_wQEAwIHgDAMBgNVHRMBAf8EAjAAMG0GA1UdIAEB_wRjMGEwXwYJKwYBBAGCNxUfMFIwUAYIKwYBBQUHAgIwRB5CAFQAQwBQAEEAIAAgAFQAcgB1AHMAdABlAGQAIAAgAFAAbABhAHQAZgBvAHIAbQAgACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDMFAGA1UdEQEB_wRGMESkQjBAMT4wEAYFZ4EFAgIMB05QQ1Q3NXgwFAYFZ4EFAgEMC2lkOjRFNTQ0MzAwMBQGBWeBBQIDDAtpZDowMDA3MDAwMjAfBgNVHSMEGDAWgBQ3yjAtSXrnaSNOtzy1PEXxOO1ZUDAdBgNVHQ4EFgQU1ml3H5Tzrs0Nev69tFNhPZnhaV0wgbIGCCsGAQUFBwEBBIGlMIGiMIGfBggrBgEFBQcwAoaBkmh0dHA6Ly9hemNzcHJvZGV1c2Fpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L2V1cy1udGMta2V5aWQtZTRhODY2NmY4ZjRjNmQ5YzM5MzJhOTQ4ODQ3NzgwYTY4MTBjNDIxMy9lMDFjMjA2Mi1mYmRjLTQwYTUtYTQwZi1jMzc3YzBmNzY1MWMuY2VyMA0GCSqGSIb3DQEBCwUAA4ICAQAz-YGrj0S841gyMZuit-qsKpKNdxbkaEhyB1baexHGcMzC2y1O1kpTrpaH3I80hrIZFtYoA2xKQ1j67uoC6vm1PhsJB6qhs9T7zmWZ1VtleJTYGNZ_bYY2wo65qJHFB5TXkevJUVe2G39kB_W1TKB6g_GSwb4a5e4D_Sjp7b7RZpyIKHT1_UE1H4RXgR9Qi68K4WVaJXJUS6T4PHrRc4PeGUoJLQFUGxYokWIf456G32GwGgvUSX76K77pVv4Y-kT3v5eEJdYxlS4EVT13a17KWd0DdLje0Ae69q_DQSlrHVLUrADvuZMeM8jxyPQvDb7ETKLsSUeHm73KOCGLStcGQ3pB49nt3d9XdWCcUwUrmbBF2G7HsRgTNbj16G6QUcWroQEqNrBG49aO9mMZ0NwSn5d3oNuXSXjLdGBXM1ukLZ-GNrZDYw5KXU102_5VpHpjIHrZh0dXg3Q9eucKe6EkFbH65-O5VaQWUnR5WJpt6-fl_l0iHqHnKXbgL6tjeerCqZWDvFsOak05R-hosAoQs_Ni0EsgZqHwR_VlG86fsSwCVU3_sDKTNs_Je08ewJ_bbMB5Tq6k1Sxs8Aw8R96EwjQLp3z-Zva1myU-KerYYVDl5BdvgPqbD8Xmst-z6vrP3CJbtr8jgqVS7RWy_cJOA8KCZ6IS_75QT7Gblq6UGFkG7zCCBuswggTToAMCAQICEzMAAAbTtnznKsOrB-gAAAAABtMwDQYJKoZIhvcNAQELBQAwgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNjA0BgNVBAMTLU1pY3Jvc29mdCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxNDAeFw0yMTA2MTAxODU0MzZaFw0yNzA2MTAxODU0MzZaMEExPzA9BgNVBAMTNkVVUy1OVEMtS0VZSUQtRTRBODY2NkY4RjRDNkQ5QzM5MzJBOTQ4ODQ3NzgwQTY4MTBDNDIxMzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJA7GLwHWWbn2H8DRppxQfre4zll1sgE3Wxt9DTYWt5-v-xKwCQb6z_7F1py7LMe58qLqglAgVhS6nEvN2puZ1GzejdsFFxz2gyEfH1y-X3RGp0dxS6UKwEtmksaMEKIRQn2GgKdUkiuvkaxaoznuExoTPyu0aXk6yFsX5KEDu9UZCgt66bRy6m3KIRnn1VK2frZfqGYi8C8x9Q69oGG316tUwAIm3ypDtv3pREXsDLYE1U5Irdv32hzJ4CqqPyau-qJS18b8CsjvgOppwXRSwpOmU7S3xqo-F7h1eeFw2tgHc7PEPt8MSSKeba8Fz6QyiLhgFr8jFUvKRzk4B41HFUMqXYawbhAtfIBiGGsGrrdNKb7MxISnH1E6yLVCQGGhXiN9U7V0h8Gn56eKzopGlubw7yMmgu8Cu2wBX_a_jFmIBHnn8YgwcRm6NvT96KclDHnFqPVm3On12bG31F7EYkIRGLbaTT6avEu9rL6AJn7Xr245Sa6dC_OSMRKqLSufxp6O6f2TH2g4kvT0Go9SeyM2_acBjIiQ0rFeBOm49H4E4VcJepf79FkljovD68imeZ5MXjxepcCzS138374Jeh7k28JePwJnjDxS8n9Dr6xOU3_wxS1gN5cW6cXSoiPGe0JM4CEyAcUtKrvpUWoTajxxnylZuvS8ou2thfH2PQlAgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAoQwGwYDVR0lBBQwEgYJKwYBBAGCNxUkBgVngQUIAzAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzASBgNVHRMBAf8ECDAGAQH_AgEAMB0GA1UdDgQWBBQ3yjAtSXrnaSNOtzy1PEXxOO1ZUDAfBgNVHSMEGDAWgBR6jArOL0hiF-KU0a5VwVLscXSkVjBwBgNVHR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUUE0lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE0LmNybDB9BggrBgEFBQcBAQRxMG8wbQYIKwYBBQUHMAKGYWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcnQwDQYJKoZIhvcNAQELBQADggIBAFZTSitCISvll6i6rPUPd8Wt2mogRw6I_c-dWQzdc9-SY9iaIGXqVSPKKOlAYU2ju7nvN6AvrIba6sngHeU0AUTeg1UZ5-bDFOWdSgPaGyH_EN_l-vbV6SJPzOmZHJOHfw2WT8hjlFaTaKYRXxzFH7PUR4nxGRbWtdIGgQhUlWg5oo_FO4bvLKfssPSONn684qkAVierq-ly1WeqJzOYhd4EylgVJ9NL3YUhg8dYcHAieptDzF7OcDqffbuZLZUx6xcyibhWQcntAh7a3xPwqXxENsHhme_bqw_kqa-NVk-Wz4zdoiNNLRvUmCSL1WLc4JPsFJ08Ekn1kW7f9ZKnie5aw-29jEf6KIBt4lGDD3tXTfaOVvWcDbu92jMOO1dhEIj63AwQiDJgZhqnrpjlyWU_X0IVQlaPBg80AE0Y3sw1oMrY0XwdeQUjSpH6e5fTYKrNB6NMT1jXGjKIzVg8XbPWlnebP2wEhq8rYiDR31b9B9Sw_naK7Xb-Cqi-VQdUtknSjeljusrBpxGUx-EIJci0-dzeXRT5_376vyKSuYxA1Xd2jd4EknJLIAVLT3rb10DCuKGLDgafbsfTBxVoEa9hSjYOZUr_m3WV6t6I9WPYjVyhyi7fCEIG4JE7YbM4na4jg5q3DM8ibE8jyufAq0PfJZTJyi7c2Q2N_9NgnCNwZ3B1YkFyZWFYdgAjAAsABAByACCd_8vzbDg65pn7mGjcbcuJ1xU4hL4oA5IsEkFYv60irgAQABAAAwAQACAek7g2C8TeORRoKxuN7HrJ5OinVGuHzEgYODyUsF9D1wAggXPPXn-Pm_4IF0c4XVaJjmHO3EB2KBwdg_L60N0IL9xoY2VydEluZm9Yof9UQ0eAFwAiAAvQNGTLa2wT6u8SKDDdwkgaq5Cmh6jcD_6ULvM9ZmvdbwAUtMInD3WtGSdWHPWijMrW_TfYo-gAAAABPuBems3Sywu4aQsGAe85iOosjtXIACIAC5FPRiZSJzjYMNnAz9zFtM62o57FJwv8F5gNEcioqhHwACIACyVXxq1wZhDsqTqdYr7vQUUJ3vwWVrlN0ZQv5HFnHqWdaGF1dGhEYXRhWKR0puqSE8mcL3SyJJKzIM9AJiqUwalQoDl_KSULYIQe8EUAAAAACJhwWMrcS4G24TDeUNy-lgAghsS2ywFz_LWf9-lC35vC9uJTVD3ZCVdweZvESUbjXnSlAQIDJiABIVggHpO4NgvE3jkUaCsbjex6yeTop1Rrh8xIGDg8lLBfQ9ciWCCBc89ef4-b_ggXRzhdVomOYc7cQHYoHB2D8vrQ3Qgv3A"
            },
            "type": "public-key"
        }"""
        challenge = base64url_to_bytes("uzn9u0Tx-LBdtGgERsbkHRBjiUt5i2rvm2BBTZrWqEo")
        rp_id = "webauthn.io"
        expected_origin = "https://webauthn.io"

        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_origin=expected_origin,
            expected_rp_id=rp_id,
        )

        assert verification.fmt == AttestationFormat.TPM
        assert verification.credential_id == base64url_to_bytes(
            "hsS2ywFz_LWf9-lC35vC9uJTVD3ZCVdweZvESUbjXnQ"
        )