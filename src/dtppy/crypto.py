import rsa
from cryptography.fernet import Fernet


def new_rsa_keys(size=512):
    """Generate a new RSA key pair."""

    public_key, private_key = rsa.newkeys(size)
    return public_key, private_key


def rsa_encrypt(public_key, plaintext):
    """Encrypt data using RSA."""

    ciphertext = rsa.encrypt(plaintext, public_key)
    return ciphertext


def rsa_decrypt(private_key, ciphertext):
    """Decrypt data using RSA."""

    plaintext = rsa.decrypt(ciphertext, private_key)
    return plaintext


def new_fernet_key():
    """Generate a new Fernet key."""

    key = Fernet.generate_key()
    return key


def fernet_encrypt(key, data):
    """Encrypt data using Fernet."""

    f = Fernet(key)
    token = f.encrypt(data)
    return token


def fernet_decrypt(key, token):
    """Decrypt data using Fernet."""

    f = Fernet(key)
    data = f.decrypt(token)
    return data
