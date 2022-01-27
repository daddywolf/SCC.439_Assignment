import socket

HOST = "0.0.0.0"
PORT = 8888


class Client:
    def __init__(self):
        self._client_socket = None

    def send_message(self, message=None):
        self._client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._client_socket.setblocking(True)
        self._client_socket.connect((HOST, PORT))
        self._client_socket.sendall(str(message).encode())
        data = self._client_socket.recv(1024)
        self._client_socket.close()
        return data


if __name__ == "__main__":
    client = Client()
    client.send_message('1')
