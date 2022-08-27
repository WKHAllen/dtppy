# Data Transfer Protocol for Python

Cross-platform networking interfaces for Python.

## Data Transfer Protocol

The Data Transfer Protocol (DTP) is a larger project to make ergonomic network programming available in any language.
See the full project [here](https://wkhallen.com/dtp/).

## Installation

Install the package:

```sh
$ python -m pip install dtppy
```

## Creating a server

A server can be built using the `Server` implementation:

```python
from dtppy import Server


# Called when data is received from a client
def receive(client_id, data):
    # Send back the length of the string
    s.send(len(data), client_id)


# Called when a client connects
def connect(client_id):
    print(f"Client with ID {client_id} connected")


# Called when a client disconnects
def disconnect(client_id):
    print(f"Client with ID {client_id} disconnected")


# Create a server that receives strings and returns the length of each string
s = Server(on_receive=receive, on_connect=connect, on_disconnect=disconnect)
s.start("127.0.0.1", 29275)
```

## Creating a client

A client can be built using the `Client` implementation:

```python
from dtppy import Client

message = "Hello, server!"


# Called when data is received from the server
def receive(data):
    # Validate the response
    print(f"Received response from server: {data}")
    assert data == len(message)


# Called when the client is disconnected from the server
def disconnected():
    print("Unexpectedly disconnected from server")


# Create a client that sends a message to the server and receives the length of the message
c = Client(on_receive=receive, on_disconnected=disconnected)
# Send the message to the server
c.send(message)
```

## Security

Information security comes included. Every message sent over a network interface is encrypted with Fernet. Key exchanges
are performed using a 512-bit RSA key-pair.
