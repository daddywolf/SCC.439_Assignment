import select
import socket
import sys

local_port = int(input("LOCAL PORT: "))
remote_port = int(input("REMOTE PORT: "))

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('0.0.0.0', local_port))
server.listen(1)
inputs = [server, sys.stdin]

while 1:
    readable, writable, exceptional = select.select(inputs, [], [])
    if server in readable:
        conn, addr = server.accept()
        data = conn.recv(1024)
        if not data: continue
        print(data.decode())
        conn.sendall("message".encode())
        conn.close()
    if sys.stdin in readable:
        message = input('message')
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(('0.0.0.0', remote_port))
        client.sendall(message.encode())
        data = client.recv(1024)
        if not data: continue
        print('Echo', data.decode())
        client.close()
