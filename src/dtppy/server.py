import errno
import pickle
import socket
import threading
import time
from contextlib import contextmanager
from typing import Any, Tuple, List, Dict, Union, Generator, Callable

import select

from .crypto import new_rsa_keys, rsa_decrypt
from .util import LEN_SIZE, DEFAULT_HOST, DEFAULT_PORT, encode_message_size, decode_message_size, construct_message, \
    deconstruct_message


class Server:
    """A socket server."""

    def __init__(self,
                 on_receive: Callable[[int, Any], None] = None,
                 on_connect: Callable[[int], None] = None,
                 on_disconnect: Callable[[int], None] = None) -> None:
        """`on_receive` is a function that will be called when a message is received from a client.
        It takes two parameters: client ID and data received.

        `on_connect` is a function that will be called when a client connects.
        It takes one parameter: client ID.

        `on_disconnect` is a function that will be called when a client disconnects.
        It takes one parameter: client ID."""

        self._on_receive: Callable[[int, Any], None] = on_receive
        self._on_connect: Callable[[int], None] = on_connect
        self._on_disconnect: Callable[[int], None] = on_disconnect
        self._serving: bool = False
        self._clients: Dict[int, socket.socket] = {}
        self._keys: Dict[int, bytes] = {}
        self._next_client_id = 0
        self._serve_thread: Union[threading.Thread, None] = None
        self._sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self, host: str = None, port: int = None) -> None:
        """Start the server."""

        if self._serving:
            raise RuntimeError("server is already serving")

        if host is None:
            host = DEFAULT_HOST
        if port is None:
            port = DEFAULT_PORT

        self._sock.bind((host, port))
        self._sock.listen()
        self._serving = True

        self._serve_thread = threading.Thread(target=self._serve)
        self._serve_thread.daemon = True
        self._serve_thread.start()

    def stop(self) -> None:
        """Stop the server."""

        if not self._serving:
            raise RuntimeError("server is not serving")

        self._serving = False

        local_client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            local_client_sock.connect(self._sock.getsockname())
        except ConnectionResetError:
            pass  # Connection reset by peer

        time.sleep(0.01)
        local_client_sock.close()

        for client_id in self._clients:
            client_sock = self._clients[client_id]
            client_sock.close()

        self._sock.close()
        self._clients = {}
        self._keys = {}

        if self._serve_thread is not None:
            if self._serve_thread is not threading.current_thread():
                self._serve_thread.join()
            self._serve_thread = None

    def send(self, data: Any, *client_ids: int) -> None:
        """Send data to clients. If no client IDs are specified, data will be sent to all clients."""

        if not self._serving:
            raise RuntimeError("server is not serving")

        if not client_ids:
            client_ids = self._clients.keys()

        for client_id in client_ids:
            if client_id in self._clients.keys():
                key = self._keys[client_id]
                conn = self._clients[client_id]
                message = construct_message(data, key)
                conn.send(message)
            else:
                raise RuntimeError(f"client {client_id} does not exist")

    def serving(self) -> bool:
        """Check whether the server is serving."""

        return self._serving

    def get_addr(self) -> Tuple[str, int]:
        """Get the address of the server."""

        if not self._serving:
            raise RuntimeError("server is not serving")

        return self._sock.getsockname()

    def get_client_addr(self, client_id: int) -> Tuple[str, int]:
        """Get the address of a client."""

        if not self._serving:
            raise RuntimeError("server is not serving")

        return self._clients[client_id].getpeername()

    def remove_client(self, client_id: int) -> None:
        """Remove a client."""

        if not self._serving:
            raise RuntimeError("server is not serving")

        if client_id not in self._clients.keys():
            raise RuntimeError(f"client {client_id} does not exist")

        conn = self._clients.pop(client_id)
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
        self._keys.pop(client_id)

    def _serve(self) -> None:
        """Serve clients."""

        while self._serving:
            try:
                socks: List[socket.socket] = list(self._clients.values())
                socks.insert(0, self._sock)
                select_result = select.select(socks, [], socks)
                read_socks: List[socket.socket] = select_result[0]
                exception_socks: List[socket.socket] = select_result[2]
            except ValueError:  # happens when a client is removed
                continue

            if not self._serving:
                return

            for notified_sock in read_socks:
                if notified_sock == self._sock:
                    try:
                        conn, _ = self._sock.accept()
                    except OSError as e:
                        if e.errno == errno.ENOTSOCK and not self._serving:
                            return
                        else:
                            raise e

                    client_id = self._new_client_id()

                    self._exchange_keys(client_id, conn)
                    self._clients[client_id] = conn
                    self._call_on_connect(client_id)
                else:
                    client_id = None

                    for sock_client_id in self._clients:
                        if self._clients[sock_client_id] == notified_sock:
                            client_id = sock_client_id

                    if client_id is not None:
                        try:
                            size = notified_sock.recv(LEN_SIZE)

                            if len(size) == 0:
                                try:
                                    self.remove_client(client_id)
                                except ValueError:
                                    pass

                                self._call_on_disconnect(client_id)
                                continue

                            message_size = decode_message_size(size)
                            message_encoded = notified_sock.recv(message_size)
                            key = self._keys[client_id]
                            message = deconstruct_message(message_encoded, key)

                            self._call_on_receive(client_id, message)
                        except OSError as e:
                            if e.errno == errno.ECONNRESET or e.errno == errno.ENOTSOCK:
                                if not self._serving:
                                    return

                                try:
                                    self.remove_client(client_id)
                                except ValueError:
                                    pass

                                self._call_on_disconnect(client_id)
                                continue
                            else:
                                raise e
                    else:
                        notified_sock.close()

            for notified_sock in exception_socks:
                client_id = None

                for sock_client_id in self._clients:
                    if self._clients[sock_client_id] == notified_sock:
                        client_id = sock_client_id

                if client_id is not None:
                    try:
                        self.remove_client(client_id)
                    except ValueError:
                        pass

                    self._call_on_disconnect(client_id)
                else:
                    notified_sock.close()

    def _exchange_keys(self, client_id: int, conn: socket.socket) -> None:
        """Exchange crypto keys with a client."""

        public_key, private_key = new_rsa_keys()
        public_key_serialized = pickle.dumps(public_key)
        size_encoded = encode_message_size(len(public_key_serialized))
        conn.send(size_encoded + public_key_serialized)

        size_encoded = conn.recv(LEN_SIZE)
        size = decode_message_size(size_encoded)
        key_encrypted = conn.recv(size)
        key = rsa_decrypt(private_key, key_encrypted)
        self._keys[client_id] = key

    def _new_client_id(self) -> int:
        """Generate a new client ID."""

        client_id = self._next_client_id
        self._next_client_id += 1
        return client_id

    def _call_on_receive(self, client_id: int, data: Any) -> None:
        """Call the receive callback."""

        if self._on_receive is not None:
            t = threading.Thread(target=self._on_receive, args=(client_id, data))
            t.daemon = True
            t.start()

    def _call_on_connect(self, client_id: int) -> None:
        """Call the connect callback."""

        if self._on_connect is not None:
            t = threading.Thread(target=self._on_connect, args=(client_id,))
            t.daemon = True
            t.start()

    def _call_on_disconnect(self, client_id: int) -> None:
        """Call the disconnect callback."""

        if self._on_disconnect is not None:
            t = threading.Thread(target=self._on_disconnect, args=(client_id,))
            t.daemon = True
            t.start()


@contextmanager
def server(host: str = None,
           port: int = None,
           on_receive: Callable[[int, Any], None] = None,
           on_connect: Callable[[int], None] = None,
           on_disconnect: Callable[[int], None] = None) -> Generator[Server, None, None]:
    """Use socket servers in a with statement."""

    s = Server(on_receive=on_receive,
               on_connect=on_connect,
               on_disconnect=on_disconnect)
    s.start(host=host, port=port)
    yield s
    s.stop()
