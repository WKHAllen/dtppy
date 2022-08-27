import errno
import pickle
import socket
import threading
import time
from contextlib import contextmanager
from typing import Any, Tuple, Union, Generator, Callable

import select

from .crypto import new_fernet_key, rsa_encrypt
from .util import LEN_SIZE, DEFAULT_HOST, DEFAULT_PORT, LOCAL_SERVER_HOST, LOCAL_SERVER_PORT, encode_message_size, \
    decode_message_size, construct_message, deconstruct_message


class Client:
    """A socket client."""

    def __init__(self,
                 on_receive: Callable[[Any], None] = None,
                 on_disconnected: Callable[[], None] = None) -> None:
        """`on_receive` is a function that will be called when a message is received from the server.
        It takes one parameter: the data received.

        `on_disconnected` is a function that will be called when the client is unexpected disconnected from the server.
        It takes no parameters."""

        self._on_receive: Callable[[Any], None] = on_receive
        self._on_disconnected: Callable[[], None] = on_disconnected
        self._connected: bool = False
        self._key: Union[bytes, None] = None
        self._handle_thread: Union[threading.Thread, None] = None
        self._sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._local_server: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self, host: str = None, port: int = None) -> None:
        """Connect to a server."""

        if self._connected:
            raise RuntimeError("client is already connected to a server")

        if host is None:
            host = DEFAULT_HOST
        if port is None:
            port = DEFAULT_PORT

        self._sock.connect((host, port))
        self._connected = True
        self._exchange_keys()

        self._handle_thread = threading.Thread(target=self._handle)
        self._handle_thread.daemon = True
        self._handle_thread.start()

    def disconnect(self) -> None:
        """Disconnect from the server."""

        if not self._connected:
            raise RuntimeError("client is not connected to a server")

        self._connected = False

        local_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            local_client_sock.connect(self._local_server.getsockname())
        except ConnectionResetError:
            pass  # Connection reset by peer

        time.sleep(0.01)
        local_client_sock.close()
        self._local_server.close()

        self._sock.close()
        self._key = None

        if self._handle_thread is not None:
            if self._handle_thread is not threading.current_thread():
                self._handle_thread.join()
            self._handle_thread = None

    def send(self, data: Any) -> None:
        """Send data to the server."""

        if not self._connected:
            raise RuntimeError("client is not connected to a server")

        message = construct_message(data, self._key)
        self._sock.send(message)

    def connected(self) -> bool:
        """Check whether the client is connected to a server."""

        return self._connected

    def get_addr(self) -> Tuple[str, int]:
        """Get the address of the client."""

        if not self._connected:
            raise RuntimeError("client is not connected to a server")

        return self._sock.getsockname()

    def get_server_addr(self) -> Tuple[str, int]:
        """Get the address of the server."""

        if not self._connected:
            raise RuntimeError("client is not connected to a server")

        return self._sock.getpeername()

    def _handle(self) -> None:
        """Handle events from the server."""

        self._local_server.bind((LOCAL_SERVER_HOST, LOCAL_SERVER_PORT))
        self._local_server.listen()

        while self._connected:
            socks = [self._sock, self._local_server]
            select.select(socks, [], socks)

            if not self._connected:
                return

            try:
                size = self._sock.recv(LEN_SIZE)

                if len(size) == 0:
                    if self._connected:
                        self.disconnect()
                        self._call_on_disconnected()

                    return

                message_size = decode_message_size(size)
                message_encoded = self._sock.recv(message_size)
                message = deconstruct_message(message_encoded, self._key)

                self._call_on_receive(message)
            except ConnectionResetError:
                self.disconnect()
                self._call_on_disconnected()
                return
            except OSError as e:
                if e.errno == errno.ENOTSOCK:
                    self.disconnect()
                    self._call_on_disconnected()
                    return
                elif e.errno == errno.ECONNABORTED and not self._connected:
                    return
                elif e.errno == errno.EAGAIN or e.errno == errno.EWOULDBLOCK:
                    continue
                else:
                    raise e

    def _exchange_keys(self) -> None:
        """Exchange crypto keys with the server."""

        size_encoded = self._sock.recv(LEN_SIZE)
        size = decode_message_size(size_encoded)
        public_key_serialized = self._sock.recv(size)
        public_key = pickle.loads(public_key_serialized)

        key = new_fernet_key()
        key_encrypted = rsa_encrypt(public_key, key)
        size_encoded = encode_message_size(len(key_encrypted))
        self._sock.send(size_encoded + key_encrypted)
        self._key = key

    def _call_on_receive(self, data: Any) -> None:
        """Call the receive callback."""

        if self._on_receive is not None:
            t = threading.Thread(target=self._on_receive, args=(data,))
            t.daemon = True
            t.start()

    def _call_on_disconnected(self) -> None:
        """Call the disconnected callback."""

        if self._on_disconnected is not None:
            t = threading.Thread(target=self._on_disconnected)
            t.daemon = True
            t.start()


@contextmanager
def client(host: str = None,
           port: int = None,
           on_receive: Callable[[Any], None] = None,
           on_disconnected: Callable[[], None] = None) -> Generator[Client, None, None]:
    """Use socket clients in a with statement."""

    c = Client(on_receive=on_receive,
               on_disconnected=on_disconnected)
    c.connect(host=host, port=port)
    yield c
    c.disconnect()
