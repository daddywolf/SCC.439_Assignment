import select
import socket
import sys

HOST = '0.0.0.0'
LOCAL_PORT = int(input("LOCAL PORT: "))
REMOTE_PORT = int(input("REMOTE PORT: "))

server = socket.socket()
server.bind((HOST, LOCAL_PORT))
server.listen(1)  # 最多可以监听1024个
server.setblocking(False)
inputs = [server, sys.stdin]
outputs = []
while True:
    readable, writeable, exceptional = select.select(inputs, outputs, inputs)  # select帮着去检测这100个链接
    print(readable, writeable, exceptional)
    for r in readable:
        if r is server:
            conn, addr = server.accept()
            print('来了个新链接', addr)
            inputs.append(conn)
        elif r is sys.stdin:
            client = socket.socket()
            client.connect((HOST, REMOTE_PORT))
            while True:
                msg = sys.stdin.readline()
                client.sendall(msg.encode())
                data = client.recv(1024)
                print('Received', repr(data))
            client.close()
            continue
        else:
            try:
                data = r.recv(1024)
                print('收到数据', data)
                r.send(data)
            except socket.error as e:
                inputs.remove(r)
