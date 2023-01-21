import os
from typing import Tuple

import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from rsa import PublicKey, PrivateKey

RSA_KEY_SIZE = 512
AES_KEY_SIZE = 32
AES_NONCE_SIZE = 12


def new_rsa_keys(key_size: int = RSA_KEY_SIZE) -> Tuple[PublicKey, PrivateKey]:
    """Generate a new RSA key pair."""

    public_key, private_key = rsa.newkeys(key_size)
    return public_key, private_key


def rsa_encrypt(public_key: PublicKey, plaintext: bytes) -> bytes:
    """Encrypt data using RSA."""

    ciphertext = rsa.encrypt(plaintext, public_key)
    return ciphertext


def rsa_decrypt(private_key: PrivateKey, ciphertext: bytes) -> bytes:
    """Decrypt data using RSA."""

    plaintext = rsa.decrypt(ciphertext, private_key)
    return plaintext


def new_aes_key(key_size: int = AES_KEY_SIZE) -> bytes:
    """Generate a new AES key."""

    key = os.urandom(key_size)
    return key


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Encrypt data using AES."""

    cipher = AESGCM(key)
    nonce = os.urandom(AES_NONCE_SIZE)
    ciphertext = cipher.encrypt(nonce, plaintext, b"")
    ciphertext_with_nonce = nonce + ciphertext
    return ciphertext_with_nonce


def aes_decrypt(key: bytes, ciphertext_with_nonce: bytes) -> bytes:
    """Decrypt data using AES."""

    cipher = AESGCM(key)
    nonce = ciphertext_with_nonce[:AES_NONCE_SIZE]
    ciphertext = ciphertext_with_nonce[AES_NONCE_SIZE:]
    plaintext = cipher.decrypt(nonce, ciphertext, b"")
    return plaintext
