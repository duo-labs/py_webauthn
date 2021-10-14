import secrets


def generate_challenge(length: int = 64) -> bytes:
    """
    Generate a random authenticator challenge
    """
    return secrets.token_bytes(length)
