import os
import random
import sys
import time
import unittest

sys.path.insert(0, os.path.split(os.path.split(os.path.abspath(__file__))[0])[0])

from src.dtppy import Server, Client, server, client
from src.dtppy.util import encode_message_size, decode_message_size
from src.dtppy.crypto import new_rsa_keys, rsa_encrypt, rsa_decrypt, new_fernet_key, fernet_encrypt, fernet_decrypt

from .expect_map import ExpectMap

WAIT_TIME = 0.2


class TestUtil(unittest.TestCase):
    def test_encode_message_size(self):
        self.assertEqual(encode_message_size(0), bytes([0, 0, 0, 0, 0]))
        self.assertEqual(encode_message_size(1), bytes([0, 0, 0, 0, 1]))
        self.assertEqual(encode_message_size(255), bytes([0, 0, 0, 0, 255]))
        self.assertEqual(encode_message_size(256), bytes([0, 0, 0, 1, 0]))
        self.assertEqual(encode_message_size(257), bytes([0, 0, 0, 1, 1]))
        self.assertEqual(encode_message_size(4311810305), bytes([1, 1, 1, 1, 1]))
        self.assertEqual(encode_message_size(4328719365), bytes([1, 2, 3, 4, 5]))
        self.assertEqual(encode_message_size(47362409218), bytes([11, 7, 5, 3, 2]))
        self.assertEqual(encode_message_size(1099511627775), bytes([255, 255, 255, 255, 255]))

    def test_decode_message_size(self):
        self.assertEqual(decode_message_size(bytes([0, 0, 0, 0, 0])), 0)
        self.assertEqual(decode_message_size(bytes([0, 0, 0, 0, 1])), 1)
        self.assertEqual(decode_message_size(bytes([0, 0, 0, 0, 255])), 255)
        self.assertEqual(decode_message_size(bytes([0, 0, 0, 1, 0])), 256)
        self.assertEqual(decode_message_size(bytes([0, 0, 0, 1, 1])), 257)
        self.assertEqual(decode_message_size(bytes([1, 1, 1, 1, 1])), 4311810305)
        self.assertEqual(decode_message_size(bytes([1, 2, 3, 4, 5])), 4328719365)
        self.assertEqual(decode_message_size(bytes([11, 7, 5, 3, 2])), 47362409218)
        self.assertEqual(decode_message_size(bytes([255, 255, 255, 255, 255])), 1099511627775)


class TestCrypto(unittest.TestCase):
    def test_rsa(self):
        message = "Hello, RSA!"

        public_key, private_key = new_rsa_keys()
        encrypted = rsa_encrypt(public_key, message.encode("utf-8"))
        decrypted = rsa_decrypt(private_key, encrypted)
        decrypted_message = decrypted.decode("utf-8")

        self.assertEqual(decrypted_message, message)

    def test_fernet(self):
        message = "Hello, Fernet!"

        key = new_fernet_key()
        encrypted = fernet_encrypt(key, message.encode("utf-8"))
        decrypted = fernet_decrypt(key, encrypted)
        decrypted_message = decrypted.decode("utf-8")

        self.assertEqual(decrypted_message, message)


class TestMain(unittest.TestCase):
    def test_server_serve(self):
        # Create expect map
        expected = ExpectMap({
            "server receive": 0,
            "server connect": 0,
            "server disconnect": 0,
        })
        self.assertEqual(expected.get_expected(), {
            "server receive": 0,
            "server connect": 0,
            "server disconnect": 0,
        })
        self.assertEqual(expected.remaining(), {})
        self.assertTrue(expected.done())

        def on_receive(client_id, data):
            expected.received("server receive")

        def on_connect(client_id):
            expected.received("server connect")

        def on_disconnect(client_id):
            expected.received("server disconnect")

        # Create server
        s = Server(on_receive=on_receive, on_connect=on_connect, on_disconnect=on_disconnect)
        self.assertFalse(s.serving())

        # Start server
        s.start()
        self.assertTrue(s.serving())
        time.sleep(WAIT_TIME)

        # Check server address info
        # print(f"Server address: {s.get_addr()}")

        # Stop server
        s.stop()
        self.assertFalse(s.serving())
        time.sleep(WAIT_TIME)

        # Check expect map
        self.assertEqual(expected.get_expected(), {
            "server receive": 0,
            "server connect": 0,
            "server disconnect": 0,
        })
        self.assertEqual(expected.remaining(), {})
        self.assertTrue(expected.done())

    def test_addresses(self):
        # Create expect map
        expected = ExpectMap({
            "server receive": 0,
            "server connect": 1,
            "server disconnect": 1,
            "client receive": 0,
            "client disconnected": 0
        })

        def server_on_receive(client_id, data):
            expected.received("server receive")

        def server_on_connect(client_id):
            expected.received("server connect")
            self.assertEqual(client_id, 0)

        def server_on_disconnect(client_id):
            expected.received("server disconnect")
            self.assertEqual(client_id, 0)

        def client_on_receive(data):
            expected.received("client receive")

        def client_on_disconnected():
            expected.received("client disconnected")

        # Create server
        s = Server(on_receive=server_on_receive, on_connect=server_on_connect, on_disconnect=server_on_disconnect)
        self.assertFalse(s.serving())
        s.start()
        self.assertTrue(s.serving())
        server_addr = s.get_addr()
        time.sleep(WAIT_TIME)

        # Create client
        c = Client(on_receive=client_on_receive, on_disconnected=client_on_disconnected)
        self.assertFalse(c.connected())
        c.connect(host=server_addr[0], port=server_addr[1])
        self.assertTrue(c.connected())
        time.sleep(WAIT_TIME)

        # Check addresses match
        self.assertEqual(s.get_addr(), c.get_server_addr())
        self.assertEqual(s.get_client_addr(0), c.get_addr())

        # Disconnect client
        c.disconnect()
        self.assertFalse(c.connected())
        time.sleep(WAIT_TIME)

        # Stop server
        s.stop()
        self.assertFalse(s.serving())
        time.sleep(WAIT_TIME)

        # Check expect map
        self.assertEqual(expected.remaining(), {})
        self.assertTrue(expected.done())

    def test_send_receive(self):
        # Create expect map
        expected = ExpectMap({
            "server receive": 1,
            "server connect": 1,
            "server disconnect": 1,
            "client receive": 1,
            "client disconnected": 0
        })

        # Messages
        server_message = "Hello, server!"
        client_message = "Hello, client!"

        def server_on_receive(client_id, data):
            expected.received("server receive")
            self.assertEqual(client_id, 0)
            self.assertEqual(data, server_message)

        def server_on_connect(client_id):
            expected.received("server connect")
            self.assertEqual(client_id, 0)

        def server_on_disconnect(client_id):
            expected.received("server disconnect")
            self.assertEqual(client_id, 0)

        def client_on_receive(data):
            expected.received("client receive")
            self.assertEqual(data, client_message)

        def client_on_disconnected():
            expected.received("client disconnected")

        # Create server
        s = Server(on_receive=server_on_receive, on_connect=server_on_connect, on_disconnect=server_on_disconnect)
        s.start()
        server_host, server_port = s.get_addr()
        time.sleep(WAIT_TIME)

        # Create client
        c = Client(on_receive=client_on_receive, on_disconnected=client_on_disconnected)
        c.connect(host=server_host, port=server_port)
        time.sleep(WAIT_TIME)

        # Send messages
        c.send(server_message)
        s.send(client_message)
        time.sleep(WAIT_TIME)

        # Disconnect client
        c.disconnect()
        time.sleep(WAIT_TIME)

        # Stop server
        s.stop()
        time.sleep(WAIT_TIME)

        # Check expect map
        self.assertEqual(expected.remaining(), {})
        self.assertTrue(expected.done())

    def test_send_different_types(self):
        # Messages
        server_messages = [False, 11, "Hello from client #0!", 1.61803398, None]
        client_messages = ["Hello from the server!", 2.718, 2 ** 64, True]
        received_server_messages = []
        received_client_messages = []

        # Create expect map
        expected = ExpectMap({
            "server receive": len(server_messages),
            "server connect": 1,
            "server disconnect": 1,
            "client receive": len(client_messages),
            "client disconnected": 0
        })

        def server_on_receive(client_id, data):
            expected.received("server receive")
            self.assertEqual(client_id, 0)
            received_server_messages.append(data)

        def server_on_connect(client_id):
            expected.received("server connect")
            self.assertEqual(client_id, 0)

        def server_on_disconnect(client_id):
            expected.received("server disconnect")
            self.assertEqual(client_id, 0)

        def client_on_receive(data):
            expected.received("client receive")
            received_client_messages.append(data)

        def client_on_disconnected():
            expected.received("client disconnected")

        # Create server
        s = Server(on_receive=server_on_receive, on_connect=server_on_connect, on_disconnect=server_on_disconnect)
        s.start()
        server_host, server_port = s.get_addr()
        time.sleep(WAIT_TIME)

        # Create client
        c = Client(on_receive=client_on_receive, on_disconnected=client_on_disconnected)
        c.connect(host=server_host, port=server_port)
        time.sleep(WAIT_TIME)

        # Send messages
        for server_message in server_messages:
            c.send(server_message)
        for client_message in client_messages:
            s.send(client_message)
        time.sleep(WAIT_TIME)

        # Check received messages match
        self.assertEqual(received_server_messages, server_messages)
        self.assertEqual(received_client_messages, client_messages)

        # Disconnect client
        c.disconnect()
        time.sleep(WAIT_TIME)

        # Stop server
        s.stop()
        time.sleep(WAIT_TIME)

        # Check expect map
        self.assertEqual(expected.remaining(), {})
        self.assertTrue(expected.done())

    def test_send_large_messages(self):
        # Create expect map
        expected = ExpectMap({
            "server receive": 1,
            "server connect": 1,
            "server disconnect": 1,
            "client receive": 1,
            "client disconnected": 0
        })

        # Messages
        large_server_message = os.urandom(random.randrange(32768, 65536))
        large_client_message = os.urandom(random.randrange(16384, 32768))

        # print(f"Large server message generated ({len(large_server_message)} bytes)")
        # print(f"Large client message generated ({len(large_client_message)} bytes)")

        def server_on_receive(client_id, data):
            expected.received("server receive")
            self.assertEqual(client_id, 0)
            self.assertEqual(data, large_server_message)

        def server_on_connect(client_id):
            expected.received("server connect")
            self.assertEqual(client_id, 0)

        def server_on_disconnect(client_id):
            expected.received("server disconnect")
            self.assertEqual(client_id, 0)

        def client_on_receive(data):
            expected.received("client receive")
            self.assertEqual(data, large_client_message)

        def client_on_disconnected():
            expected.received("client disconnected")

        # Create server
        s = Server(on_receive=server_on_receive, on_connect=server_on_connect, on_disconnect=server_on_disconnect)
        s.start()
        server_host, server_port = s.get_addr()
        time.sleep(WAIT_TIME)

        # Create client
        c = Client(on_receive=client_on_receive, on_disconnected=client_on_disconnected)
        c.connect(host=server_host, port=server_port)
        time.sleep(WAIT_TIME)

        # Send messages
        c.send(large_server_message)
        s.send(large_client_message)
        time.sleep(WAIT_TIME)

        # Disconnect client
        c.disconnect()
        time.sleep(WAIT_TIME)

        # Stop server
        s.stop()
        time.sleep(WAIT_TIME)

        # Check expect map
        self.assertEqual(expected.remaining(), {})
        self.assertTrue(expected.done())

    def test_sending_numerous_messages(self):
        # Messages
        num_server_messages = random.randrange(64, 128)
        num_client_messages = random.randrange(128, 256)
        server_messages = []
        client_messages = []
        received_server_messages = []
        received_client_messages = []
        for i in range(num_server_messages):
            server_messages.append(random.randrange(1024))
        for i in range(num_client_messages):
            client_messages.append(random.randrange(1024))
        # print(f"Generated {num_server_messages} server messages")
        # print(f"Generated {num_client_messages} client messages")

        # Create expect map
        expected = ExpectMap({
            "server receive": num_server_messages,
            "server connect": 1,
            "server disconnect": 1,
            "client receive": num_client_messages,
            "client disconnected": 0
        })

        def server_on_receive(client_id, data):
            expected.received("server receive")
            self.assertEqual(client_id, 0)
            received_server_messages.append(data)

        def server_on_connect(client_id):
            expected.received("server connect")
            self.assertEqual(client_id, 0)

        def server_on_disconnect(client_id):
            expected.received("server disconnect")
            self.assertEqual(client_id, 0)

        def client_on_receive(data):
            expected.received("client receive")
            received_client_messages.append(data)

        def client_on_disconnected():
            expected.received("client disconnected")

        # Create server
        s = Server(on_receive=server_on_receive, on_connect=server_on_connect, on_disconnect=server_on_disconnect)
        s.start()
        server_host, server_port = s.get_addr()
        time.sleep(WAIT_TIME)

        # Create client
        c = Client(on_receive=client_on_receive, on_disconnected=client_on_disconnected)
        c.connect(host=server_host, port=server_port)
        time.sleep(WAIT_TIME)

        # Send messages
        for server_message in server_messages:
            c.send(server_message)
        for client_message in client_messages:
            s.send(client_message)
        time.sleep(WAIT_TIME)

        # Check messages match
        self.assertEqual(server_messages, received_server_messages)
        self.assertEqual(client_messages, received_client_messages)

        # Disconnect client
        c.disconnect()
        time.sleep(WAIT_TIME)

        # Stop server
        s.stop()
        time.sleep(WAIT_TIME)

        # Check expect map
        self.assertEqual(expected.remaining(), {})
        self.assertTrue(expected.done())

    def test_multiple_clients(self):
        # Create expect map
        expected = ExpectMap({
            "server receive": 2,
            "server connect": 2,
            "server disconnect": 2,
            "client 1 receive": 2,
            "client 2 receive": 2,
            "client disconnected": 0
        })

        # Messages
        message_from_client1 = "Hello from client #1!"
        message_from_client2 = "Goodbye from client #2!"
        message_from_server = "Hello from the server :)"
        receiving_message_from_server = False

        def server_on_receive(client_id, data):
            expected.received("server receive")
            self.assertTrue(client_id in [0, 1])

            if client_id == 0:
                self.assertEqual(data, message_from_client1)
            elif client_id == 1:
                self.assertEqual(data, message_from_client2)

            s.send(len(data), client_id)

        def server_on_connect(client_id):
            expected.received("server connect")
            self.assertTrue(client_id in [0, 1])

        def server_on_disconnect(client_id):
            expected.received("server disconnect")
            self.assertTrue(client_id in [0, 1])

        def client1_on_receive(data):
            expected.received("client 1 receive")

            if receiving_message_from_server:
                self.assertEqual(data, message_from_server)
            else:
                self.assertEqual(data, len(message_from_client1))

        def client2_on_receive(data):
            expected.received("client 2 receive")

            if receiving_message_from_server:
                self.assertEqual(data, message_from_server)
            else:
                self.assertEqual(data, len(message_from_client2))

        def client_on_disconnected():
            expected.received("client disconnected")

        # Create server
        s = Server(on_receive=server_on_receive, on_connect=server_on_connect, on_disconnect=server_on_disconnect)
        s.start()
        server_host, server_port = s.get_addr()
        time.sleep(WAIT_TIME)

        # Create client 1
        c1 = Client(on_receive=client1_on_receive, on_disconnected=client_on_disconnected)
        c1.connect(host=server_host, port=server_port)
        time.sleep(WAIT_TIME)

        # Check client 1 address info
        self.assertEqual(c1.get_addr(), s.get_client_addr(0))
        self.assertEqual(c1.get_server_addr(), s.get_addr())

        # Create client 2
        c2 = Client(on_receive=client2_on_receive, on_disconnected=client_on_disconnected)
        c2.connect(host=server_host, port=server_port)
        time.sleep(WAIT_TIME)

        # Check client 2 address info
        self.assertEqual(c2.get_addr(), s.get_client_addr(1))
        self.assertEqual(c2.get_server_addr(), s.get_addr())

        # Send message from client 1
        c1.send(message_from_client1)
        time.sleep(WAIT_TIME)

        # Send message from client 2
        c2.send(message_from_client2)
        time.sleep(WAIT_TIME)

        # Send message to all clients
        receiving_message_from_server = True
        s.send(message_from_server)
        time.sleep(WAIT_TIME)

        # Disconnect client 1
        c1.disconnect()
        time.sleep(WAIT_TIME)

        # Disconnect client 2
        c2.disconnect()
        time.sleep(WAIT_TIME)

        # Stop server
        s.stop()
        time.sleep(WAIT_TIME)

        # Check expect map
        self.assertEqual(expected.remaining(), {})
        self.assertTrue(expected.done())

    def test_client_disconnected(self):
        # Create expect map
        expected = ExpectMap({
            "server receive": 0,
            "server connect": 1,
            "server disconnect": 0,
            "client receive": 0,
            "client disconnected": 1
        })

        def server_on_receive(client_id, data):
            expected.received("server receive")

        def server_on_connect(client_id):
            expected.received("server connect")

        def server_on_disconnect(client_id):
            expected.received("server disconnect")

        def client_on_receive(data):
            expected.received("client receive")

        def client_on_disconnected():
            expected.received("client disconnected")

        # Create server
        s = Server(on_receive=server_on_receive, on_connect=server_on_connect, on_disconnect=server_on_disconnect)
        self.assertFalse(s.serving())
        s.start()
        self.assertTrue(s.serving())
        server_host, server_port = s.get_addr()
        time.sleep(WAIT_TIME)

        # Create client
        c = Client(on_receive=client_on_receive, on_disconnected=client_on_disconnected)
        self.assertFalse(c.connected())
        c.connect(host=server_host, port=server_port)
        self.assertTrue(c.connected())
        time.sleep(WAIT_TIME)

        # Stop server
        self.assertTrue(s.serving())
        self.assertTrue(c.connected())
        s.stop()
        self.assertFalse(s.serving())
        time.sleep(WAIT_TIME)
        self.assertFalse(c.connected())

        # Check expect map
        self.assertEqual(expected.remaining(), {})
        self.assertTrue(expected.done())

    def test_remove_client(self):
        # Create expect map
        expected = ExpectMap({
            "server receive": 0,
            "server connect": 1,
            "server disconnect": 0,
            "client receive": 0,
            "client disconnected": 1
        })

        def server_on_receive(client_id, data):
            expected.received("server receive")

        def server_on_connect(client_id):
            expected.received("server connect")

        def server_on_disconnect(client_id):
            expected.received("server disconnect")

        def client_on_receive(data):
            expected.received("client receive")

        def client_on_disconnected():
            expected.received("client disconnected")

        # Create server
        s = Server(on_receive=server_on_receive, on_connect=server_on_connect, on_disconnect=server_on_disconnect)
        s.start()
        server_host, server_port = s.get_addr()
        time.sleep(WAIT_TIME)

        # Create client
        c = Client(on_receive=client_on_receive, on_disconnected=client_on_disconnected)
        self.assertFalse(c.connected())
        c.connect(host=server_host, port=server_port)
        self.assertTrue(c.connected())
        time.sleep(WAIT_TIME)

        # Disconnect the client
        self.assertTrue(c.connected())
        s.remove_client(0)
        time.sleep(WAIT_TIME)
        self.assertFalse(c.connected())

        # Stop server
        s.stop()
        time.sleep(WAIT_TIME)

        # Check expect map
        self.assertEqual(expected.remaining(), {})
        self.assertTrue(expected.done())

    def test_server_client_address_defaults(self):
        # Create server with host
        s1 = Server()
        s1.start(host="127.0.0.1")
        server_host, server_port = s1.get_addr()
        time.sleep(WAIT_TIME)

        # Create client
        c1 = Client()
        c1.connect(host=server_host, port=server_port)
        time.sleep(WAIT_TIME)

        # Disconnect client
        c1.disconnect()
        time.sleep(WAIT_TIME)

        # Stop server
        s1.stop()
        time.sleep(WAIT_TIME)

        # Create server with port
        s2 = Server()
        s2.start(port=35792)
        server_host, server_port = s2.get_addr()
        time.sleep(WAIT_TIME)

        # Create client
        c2 = Client()
        c2.connect(host=server_host, port=server_port)
        time.sleep(WAIT_TIME)

        # Disconnect client
        c2.disconnect()
        time.sleep(WAIT_TIME)

        # Stop server
        s2.stop()
        time.sleep(WAIT_TIME)

        # Create server with host and port
        s3 = Server()
        s3.start(host="127.0.0.1", port=35792)
        server_host, server_port = s3.get_addr()
        time.sleep(WAIT_TIME)

        # Create client
        c3 = Client()
        c3.connect(host=server_host, port=server_port)
        time.sleep(WAIT_TIME)

        # Disconnect client
        c3.disconnect()
        time.sleep(WAIT_TIME)

        # Stop server
        s3.stop()
        time.sleep(WAIT_TIME)

    def test_with_statements(self):
        # Create expect map
        expected = ExpectMap({
            "server receive": 1,
            "server connect": 1,
            "server disconnect": 1,
            "client receive": 1,
            "client disconnected": 0
        })

        # Messages
        server_message = "Hello, server!"
        client_message = "Hello, client #0!"

        def server_on_receive(client_id, data):
            expected.received("server receive")
            self.assertEqual(client_id, 0)
            self.assertEqual(data, server_message)

        def server_on_connect(client_id):
            expected.received("server connect")
            self.assertEqual(client_id, 0)

        def server_on_disconnect(client_id):
            expected.received("server disconnect")
            self.assertEqual(client_id, 0)

        def client_on_receive(data):
            expected.received("client receive")
            self.assertEqual(data, client_message)

        def client_on_disconnected():
            expected.received("client disconnected")

        # Create server
        with server(on_receive=server_on_receive,
                    on_connect=server_on_connect,
                    on_disconnect=server_on_disconnect) as s:
            server_host, server_port = s.get_addr()

            # Create client
            with client(host=server_host,
                        port=server_port,
                        on_receive=client_on_receive,
                        on_disconnected=client_on_disconnected) as c:
                c.send(server_message)
                s.send(client_message)
                time.sleep(WAIT_TIME)

            time.sleep(WAIT_TIME)

        # Check expect map
        self.assertEqual(expected.remaining(), {})
        self.assertTrue(expected.done())


if __name__ == "__main__":
    unittest.main()
