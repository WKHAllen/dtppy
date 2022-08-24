import pickle
import socket
from typing import Any

from .crypto import fernet_encrypt, fernet_decrypt

LEN_SIZE: int = 5

DEFAULT_HOST: str = socket.gethostbyname(socket.gethostname())
DEFAULT_PORT: int = 29275

LOCAL_SERVER_HOST: str = "127.0.0.1"
LOCAL_SERVER_PORT: int = 0


def encode_message_size(size: int) -> bytes:
    """Encode the size portion of a message."""

    encoded_size = b""

    for i in range(LEN_SIZE):
        encoded_size = bytes([size & 0xff]) + encoded_size
        size >>= 8

    return encoded_size


def decode_message_size(encoded_size: bytes) -> int:
    """Decode the size portion of a message."""

    size = 0

    for i in range(LEN_SIZE):
        size <<= 8
        size += encoded_size[i]

    return size


def construct_message(data: Any, key: bytes) -> bytes:
    """Construct a message to be sent through a socket."""

    message_serialized = pickle.dumps(data)
    message_encrypted = fernet_encrypt(key, message_serialized)
    message_size = encode_message_size(len(message_encrypted))
    return message_size + message_encrypted


def deconstruct_message(data: bytes, key: bytes) -> Any:
    """Deconstruct a message that came from a socket."""

    message_decrypted = fernet_decrypt(key, data)
    message_deserialized = pickle.loads(message_decrypted)
    return message_deserialized
