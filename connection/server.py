import socket

from utils.message import Message

HOST = '0.0.0.0'
PORT = 8888


class Server:
    def __init__(self):
        self._server_socket = None

    def open_server(self):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.bind((HOST, PORT))
        self._server_socket.listen(1)
        print(f"Server is up at {HOST}:{PORT}, waiting for the connection...")

    def receive_message(self, message=None):
        while True:
            conn, addr = self._server_socket.accept()
            print('Connected by', addr)
            data = conn.recv(1024)
            if not data: break
            print("data received: " + data.decode())
            conn.sendall(str(message).encode())
            conn.close()
        return data

    def close_server(self):
        if self._server_socket:
            self._server_socket.close()


if __name__ == "__main__":
    server = Server()
    server.open_server()
    data = server.receive_message()
    print(data)
