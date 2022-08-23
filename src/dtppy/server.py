import errno
import pickle
import socket
import threading
import time
from contextlib import contextmanager

import select

from .crypto import new_rsa_keys, rsa_decrypt
from .util import LEN_SIZE, DEFAULT_HOST, DEFAULT_PORT, encode_message_size, decode_message_size, construct_message, \
    deconstruct_message


class Server:
    """A socket server."""

    def __init__(self, on_receive=None, on_connect=None, on_disconnect=None):
        """`on_receive` is a function that will be called when a message is received from a client.
            It takes two parameters: client ID and data received.
        `on_connect` is a function that will be called when a client connects.
            It takes one parameter: client ID.
        `on_disconnect` is a function that will be called when a client disconnects.
            It takes one parameter: client ID."""

        self._on_receive = on_receive
        self._on_connect = on_connect
        self._on_disconnect = on_disconnect
        self._serving = False
        self._clients = {}
        self._keys = {}
        self._next_client_id = 0
        self._serveThread = None
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self, host=None, port=None):
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

        self._serveThread = threading.Thread(target=self._serve)
        self._serveThread.daemon = True
        self._serveThread.start()

    def stop(self):
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
            self._clients[client_id].close()

        self._sock.close()
        self._clients = {}
        self._keys = {}

        if self._serveThread is not None:
            if self._serveThread is not threading.current_thread():
                self._serveThread.join()
            self._serveThread = None

    def send(self, data, *client_ids):
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

    def serving(self):
        """Check whether the server is serving."""

        return self._serving

    def get_addr(self):
        """Get the address of the server."""

        if not self._serving:
            raise RuntimeError("server is not serving")

        return self._sock.getsockname()

    def get_client_addr(self, client_id):
        """Get the address of a client."""

        if not self._serving:
            raise RuntimeError("server is not serving")

        return self._clients[client_id].getpeername()

    def remove_client(self, client_id):
        """Remove a client."""

        if not self._serving:
            raise RuntimeError("server is not serving")

        if client_id not in self._clients.keys():
            raise RuntimeError(f"client {client_id} does not exist")

        conn = self._clients[client_id]
        conn.close()
        self._clients.pop(conn)
        self._keys.pop(conn)

    def _serve(self):
        """Serve clients."""

        while self._serving:
            try:
                socks = list(self._clients.values())
                socks.insert(0, self._sock)
                read_socks, _, exception_socks = select.select(socks, [], socks)
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

            for notified_sock in exception_socks:
                client_id = None

                for sock_client_id in self._clients:
                    if self._clients[sock_client_id] == notified_sock:
                        client_id = sock_client_id

                try:
                    self.remove_client(client_id)
                except ValueError:
                    pass

                self._call_on_disconnect(client_id)

    def _exchange_keys(self, client_id, conn):
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

    def _new_client_id(self):
        """Generate a new client ID."""

        client_id = self._next_client_id
        self._next_client_id += 1
        return client_id

    def _call_on_receive(self, client_id, data):
        """Call the receive callback."""

        if self._on_receive is not None:
            t = threading.Thread(target=self._on_receive, args=(client_id, data))
            t.daemon = True
            t.start()

    def _call_on_connect(self, client_id):
        """Call the connect callback."""

        if self._on_connect is not None:
            t = threading.Thread(target=self._on_connect, args=(client_id,))
            t.daemon = True
            t.start()

    def _call_on_disconnect(self, client_id):
        """Call the disconnect callback."""

        if self._on_disconnect is not None:
            t = threading.Thread(target=self._on_disconnect, args=(client_id,))
            t.daemon = True
            t.start()


@contextmanager
def server(host, port, *args, **kwargs):
    """Use socket servers in a with statement."""

    s = Server(*args, **kwargs)
    s.start(host, port)
    yield s
    s.stop()
