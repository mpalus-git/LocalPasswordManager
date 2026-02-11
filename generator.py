import secrets
import string


_LOWERCASE = string.ascii_lowercase
_UPPERCASE = string.ascii_uppercase
_DIGITS = string.digits
_SPECIAL = "!@#$%^&*()-_=+[]{}|;:,.<>?"

_ALL_CHARS = _LOWERCASE + _UPPERCASE + _DIGITS + _SPECIAL

MIN_LENGTH = 8
MAX_LENGTH = 128
DEFAULT_LENGTH = 16


def generate_password(length: int = DEFAULT_LENGTH) -> str:
    if length < MIN_LENGTH:
        raise ValueError(f"Minimalna długość hasła to {MIN_LENGTH} znaków.")
    if length > MAX_LENGTH:
        raise ValueError(f"Maksymalna długość hasła to {MAX_LENGTH} znaków.")

    password_chars = [
        secrets.choice(_LOWERCASE),
        secrets.choice(_UPPERCASE),
        secrets.choice(_DIGITS),
        secrets.choice(_SPECIAL),
    ]

    for _ in range(length - 4):
        password_chars.append(secrets.choice(_ALL_CHARS))

    rng = secrets.SystemRandom()
    rng.shuffle(password_chars)

    return "".join(password_chars)
