import pickle
import socket

from .crypto import fernet_encrypt, fernet_decrypt

LEN_SIZE = 5

DEFAULT_HOST = socket.gethostbyname(socket.gethostname())
DEFAULT_PORT = 29275

LOCAL_SERVER_HOST = "127.0.0.1"
LOCAL_SERVER_PORT = 0


def encode_message_size(size):
    """Encode the size portion of a message."""

    encoded_size = b""

    for i in range(LEN_SIZE):
        encoded_size = bytes([size & 0xff]) + encoded_size
        size >>= 8

    return encoded_size


def decode_message_size(encoded_size):
    """Decode the size portion of a message."""

    size = 0

    for i in range(LEN_SIZE):
        size <<= 8
        size += encoded_size[i]

    return size


def construct_message(data, key):
    """Construct a message to be sent through a socket."""

    message_serialized = pickle.dumps(data)
    message_encrypted = fernet_encrypt(key, message_serialized)
    message_size = encode_message_size(message_encrypted)
    return message_size + message_encrypted


def deconstruct_message(data, key):
    """Deconstruct a message that came from a socket."""

    message_decrypted = fernet_decrypt(key, data)
    message_deserialized = pickle.loads(message_decrypted)
    return message_deserialized
