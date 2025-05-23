import datetime
from typing import Optional


def verify_safetynet_timestamp(
    timestamp_ms: int,
    *,
    time: Optional[datetime.datetime] = None,
) -> None:
    """Handle time drift between an RP and the Google SafetyNet API servers with a window of
    time within which the response is valid
    """
    if time is None:
        time = datetime.datetime.now(datetime.timezone.utc)

    # Buffer period in ms
    grace_ms = 10 * 1000
    # Get "now" in ms
    now = int(time.timestamp()) * 1000

    # Make sure the response was generated in the past
    if timestamp_ms > (now + grace_ms):
        raise ValueError(f"Payload timestamp {timestamp_ms} was later than {now} + {grace_ms}")

    # Make sure the response arrived within the grace period
    if timestamp_ms < (now - grace_ms):
        raise ValueError("Payload has expired")
