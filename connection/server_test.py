import socket

HOST = '0.0.0.0'  # Symbolic name meaning all available interfaces
PORT = 8888  # Arbitrary non-privileged port
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)
conn, addr = s.accept()
with conn:
    print('Connected by', addr)
    while True:
        data = conn.recv(1024)
        print(f"Received: {data.decode()}")
        if not data: break
        conn.sendall(data)