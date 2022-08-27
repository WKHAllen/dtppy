from typing import Tuple

import rsa
from cryptography.fernet import Fernet
from rsa import PublicKey, PrivateKey


def new_rsa_keys(size: int = 512) -> Tuple[PublicKey, PrivateKey]:
    """Generate a new RSA key pair."""

    public_key, private_key = rsa.newkeys(size)
    return public_key, private_key


def rsa_encrypt(public_key: PublicKey, plaintext: bytes) -> bytes:
    """Encrypt data using RSA."""

    ciphertext = rsa.encrypt(plaintext, public_key)
    return ciphertext


def rsa_decrypt(private_key: PrivateKey, ciphertext: bytes) -> bytes:
    """Decrypt data using RSA."""

    plaintext = rsa.decrypt(ciphertext, private_key)
    return plaintext


def new_fernet_key() -> bytes:
    """Generate a new Fernet key."""

    key = Fernet.generate_key()
    return key


def fernet_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt data using Fernet."""

    f = Fernet(key)
    ciphertext = f.encrypt(plaintext)
    return ciphertext


def fernet_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """Decrypt data using Fernet."""

    f = Fernet(key)
    plaintext = f.decrypt(ciphertext)
    return plaintext
