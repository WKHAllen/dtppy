import os
import sys

sys.path.insert(0, os.path.split(os.path.split(os.path.abspath(__file__))[0])[0])
from dtppy import Client, Server, client, server
import time


def main():
    waitTime = 0.1

    thisDir = os.path.split(os.path.abspath(__file__))[0]

    serverResult = []
    clientResult = []

    def serverRecv(conn, data, datatype):
        serverResult.append(data)

    def clientRecv(data, datatype):
        clientResult.append(data)

    s = Server(serverRecv, jsonEncode=True)
    s.start()
    print(s.getAddr())
    time.sleep(waitTime)
    c = Client(clientRecv, jsonEncode=True)
    c.connect(*s.getAddr())
    time.sleep(waitTime)
    c.send("Hello, world!")
    s.send("foo bar")
    time.sleep(waitTime)
    c.disconnect()
    time.sleep(waitTime)
    s.stop()
    time.sleep(waitTime)

    assert serverResult == ["Hello, world!"]
    assert clientResult == ["foo bar"]

    serverResult = []
    clientResult = []

    with server(None, None, onRecv=serverRecv, recvDir=f"{thisDir}/serverRecv") as s:
        with client(*s.getAddr(), onRecv=clientRecv, recvDir=f"{thisDir}/clientRecv") as c:
            c.sendFile(f"{thisDir}/files")
            s.sendFile(f"{thisDir}/files/test.txt")
            time.sleep(waitTime)

    assert serverResult == ["files"]
    assert clientResult == ["test.txt"]
    time.sleep(waitTime)

    connect = []
    disconnect = []
    disconnected = []

    def onConnect(conn):
        connect.append(conn)

    def onDisconnect(conn):
        disconnect.append(conn)

    def onDisconnected():
        disconnected.append(True)

    s = Server(onConnect=onConnect, onDisconnect=onDisconnect)
    s.start()
    time.sleep(waitTime)

    c1 = Client(onDisconnected=onDisconnected)
    c1.connect(*s.getAddr())
    time.sleep(waitTime)
    client1 = s.getClients()[0]
    time.sleep(waitTime)
    c1.disconnect()
    time.sleep(waitTime)

    c2 = Client(onDisconnected=onDisconnected)
    c2.connect(*s.getAddr())
    time.sleep(waitTime)
    client2 = s.getClients()[0]
    s.stop()
    time.sleep(waitTime)

    assert connect == [client1, client2]
    assert disconnect == [client1]
    assert disconnected == [True]


if __name__ == "__main__":
    main()
