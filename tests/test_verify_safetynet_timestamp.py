import datetime
from unittest import TestCase

from webauthn.helpers import verify_safetynet_timestamp


class TestVerifySafetyNetTimestamp(TestCase):
    now_ms = 1636589648000
    now_dt = datetime.datetime.fromtimestamp(now_ms / 1000, datetime.timezone.utc)

    def test_does_not_raise_on_timestamp_slightly_in_future(self):
        # Put timestamp just a bit in the future
        timestamp_ms = self.now_ms + 600
        verify_safetynet_timestamp(timestamp_ms, time=self.now_dt)

        assert True

    def test_does_not_raise_on_timestamp_slightly_in_past(self):
        # Put timestamp just a bit in the past
        timestamp_ms = self.now_ms - 600
        verify_safetynet_timestamp(timestamp_ms, time=self.now_dt)

        assert True

    def test_raises_on_timestamp_too_far_in_future(self):
        # Put timestamp 20 seconds in the future
        timestamp_ms = self.now_ms + 20000
        self.assertRaisesRegex(
            ValueError,
            "was later than",
            lambda: verify_safetynet_timestamp(timestamp_ms, time=self.now_dt)
        )

    def test_raises_on_timestamp_too_far_in_past(self):
        # Put timestamp 20 seconds in the past
        timestamp_ms = self.now_ms - 20000
        self.assertRaisesRegex(
            ValueError,
            "expired",
            lambda: verify_safetynet_timestamp(timestamp_ms, time=self.now_dt)
        )

    def test_does_not_raise_on_last_possible_millisecond(self):
        # Timestamp is verified at the exact last millisecond
        timestamp_ms = self.now_ms + 10000
        verify_safetynet_timestamp(timestamp_ms, time=self.now_dt)

        assert True
