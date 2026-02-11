import os
import base64

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


_VERIFICATION_PLAINTEXT = b"MASTER_PASSWORD_VALID"

_KDF_ITERATIONS = 600_000
_SALT_LENGTH = 16


def generate_salt() -> bytes:
    return os.urandom(_SALT_LENGTH)


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_KDF_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode("utf-8")))


def encrypt_password(key: bytes, plaintext: str) -> bytes:
    f = Fernet(key)
    return f.encrypt(plaintext.encode("utf-8"))


def decrypt_password(key: bytes, token: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(token).decode("utf-8")


def create_verification_token(key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(_VERIFICATION_PLAINTEXT)


def verify_master_password(key: bytes, token: bytes) -> bool:
    try:
        f = Fernet(key)
        plaintext = f.decrypt(token)
        return plaintext == _VERIFICATION_PLAINTEXT
    except InvalidToken:
        return False
