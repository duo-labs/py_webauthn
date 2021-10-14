from unittest import TestCase

from webauthn.helpers.generate_challenge import generate_challenge


class TestWebAuthnGenerateChallenge(TestCase):
    def test_generates_byte_sequence(self) -> None:
        output = generate_challenge()

        assert type(output) == bytes
        assert len(output) == 64

    def test_generates_unique_value_each_time(self) -> None:
        output1 = generate_challenge()
        output2 = generate_challenge()

        assert output1 != output2

    def test_supports_custom_lengths(self) -> None:
        output = generate_challenge(32)

        assert len(output) == 32
