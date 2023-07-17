import pytest
from base64 import urlsafe_b64encode
from typing import Union
from unittest import TestCase

from webauthn import verify_authentication_response, base64url_to_bytes
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticationCredential,
    AuthenticatorAssertionResponse,
)


class TestWebAuthnBytesSubclassSupport(TestCase):
    def test_handles_bytes_subclasses(self) -> None:
        """
        Ensure the library can support being used in projects that might work with values that are
        subclasses of `bytes`. Let's embrace Python's duck-typing, not shy away from it
        """

        class CustomBytes(bytes):
            def __new__(cls, data: Union[str, bytes]):
                return bytes.__new__(cls, data.encode("ascii") if isinstance(data, str) else data)

        verification = verify_authentication_response(
            credential=AuthenticationCredential(
                id="fq9Nj0nS24B5y6Pkw_h3-9GEAEA3-0LBPxE2zvTdLjDqtSeCSNYFe9VMRueSpAZxT3YDc6L1lWXdQNwI-sVNYrefEcRR1Nsb_0jpHE955WEtFud2xxZg3MvoLMxHLet63i5tajd1fHtP7I-00D6cehM8ZWlLp2T3s9lfZgVIFcA",
                raw_id=CustomBytes(
                    "fq9Nj0nS24B5y6Pkw_h3-9GEAEA3-0LBPxE2zvTdLjDqtSeCSNYFe9VMRueSpAZxT3YDc6L1lWXdQNwI-sVNYrefEcRR1Nsb_0jpHE955WEtFud2xxZg3MvoLMxHLet63i5tajd1fHtP7I-00D6cehM8ZWlLp2T3s9lfZgVIFcA"
                ),
                response=AuthenticatorAssertionResponse(
                    authenticator_data=CustomBytes(
                        "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAABw"
                    ),
                    client_data_json=CustomBytes(
                        "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZVo0ZWVBM080ank1Rkl6cURhU0o2SkROR3UwYkJjNXpJMURqUV9rTHNvMVdOcWtHNms1bUNZZjFkdFFoVlVpQldaV2xaa3pSNU1GZWVXQ3BKUlVOWHciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
                    ),
                    signature=CustomBytes(
                        "RRWV8mYDRvK7YdQgdtZD4pJ2dh1D_IWZ_D6jsZo6FHJBoenbj0CVT5nA20vUzlRhN4R6dOEUHmUwP1F8eRBhBg"
                    ),
                ),
            ),
            expected_challenge=CustomBytes(
                base64url_to_bytes("eZ4eeA3O4jy5FIzqDaSJ6JDNGu0bBc5zI1DjQ_kLso1WNqkG6k5mCYf1dtQhVUiBWZWlZkzR5MFeeWCpJRUNXw")
            ),
            expected_rp_id="localhost",
            expected_origin="http://localhost:5000",
            credential_public_key=CustomBytes(
                base64url_to_bytes("pAEBAycgBiFYIMz6_SUFLiDid2Yhlq0YboyJ-CDrIrNpkPUGmJp4D3Dp")
            ),
            credential_current_sign_count=3,
        )

        assert verification.new_sign_count == 7

    def test_handles_memoryviews(self) -> None:
        """
        Ensure support for libraries that leverage memoryviews
        """

        def as_memoryview(data: Union[str, bytes]) -> memoryview:
            return memoryview(data.encode("ascii") if isinstance(data, str) else data)

        verification = verify_authentication_response(
            credential=AuthenticationCredential(
                id="fq9Nj0nS24B5y6Pkw_h3-9GEAEA3-0LBPxE2zvTdLjDqtSeCSNYFe9VMRueSpAZxT3YDc6L1lWXdQNwI-sVNYrefEcRR1Nsb_0jpHE955WEtFud2xxZg3MvoLMxHLet63i5tajd1fHtP7I-00D6cehM8ZWlLp2T3s9lfZgVIFcA",
                raw_id=as_memoryview(
                    "fq9Nj0nS24B5y6Pkw_h3-9GEAEA3-0LBPxE2zvTdLjDqtSeCSNYFe9VMRueSpAZxT3YDc6L1lWXdQNwI-sVNYrefEcRR1Nsb_0jpHE955WEtFud2xxZg3MvoLMxHLet63i5tajd1fHtP7I-00D6cehM8ZWlLp2T3s9lfZgVIFcA"
                ),
                response=AuthenticatorAssertionResponse(
                    authenticator_data=as_memoryview(
                        "SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MBAAAABw"
                    ),
                    client_data_json=as_memoryview(
                        "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZVo0ZWVBM080ank1Rkl6cURhU0o2SkROR3UwYkJjNXpJMURqUV9rTHNvMVdOcWtHNms1bUNZZjFkdFFoVlVpQldaV2xaa3pSNU1GZWVXQ3BKUlVOWHciLCJvcmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
                    ),
                    signature=as_memoryview(
                        "RRWV8mYDRvK7YdQgdtZD4pJ2dh1D_IWZ_D6jsZo6FHJBoenbj0CVT5nA20vUzlRhN4R6dOEUHmUwP1F8eRBhBg"
                    ),
                ),
            ),
            expected_challenge=as_memoryview(
                base64url_to_bytes("eZ4eeA3O4jy5FIzqDaSJ6JDNGu0bBc5zI1DjQ_kLso1WNqkG6k5mCYf1dtQhVUiBWZWlZkzR5MFeeWCpJRUNXw")
            ),
            expected_rp_id="localhost",
            expected_origin="http://localhost:5000",
            credential_public_key=as_memoryview(
                base64url_to_bytes("pAEBAycgBiFYIMz6_SUFLiDid2Yhlq0YboyJ-CDrIrNpkPUGmJp4D3Dp")
            ),
            credential_current_sign_count=3,
        )

        assert verification.new_sign_count == 7

    def test_supports_strings_for_bytes(self) -> None:
        """
        Preserve the ability to pass strings for `bytes` fields
        """
        response = AuthenticatorAssertionResponse(
            authenticator_data=bytes(),
            client_data_json=bytes(),
            signature=bytes(),
            user_handle=urlsafe_b64encode(b'some_user_handle_string').decode('ascii'), # type: ignore
        )

        self.assertEqual(response.user_handle, b'some_user_handle_string')
