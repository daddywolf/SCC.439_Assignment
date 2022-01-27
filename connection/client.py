import random
import socket

from utils.message import Message


class Client:
    def __init__(self, ip='0.0.0.0', port=8888):
        self._client_socket = None
        self._ip = ip
        self._port = port

    def send_message(self, message=None):
        self._client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._client_socket.setblocking(True)
        self._client_socket.connect((self._ip, self._port))
        print(f"Client is connected at {self._ip}:{self._port}")
        self._client_socket.sendall(message.encode())
        data = self._client_socket.recv(1024)
        print(f"Message {str(message).encode()} sent. Response: {data}")
        self._client_socket.close()
        return data


if __name__ == "__main__":
    client = Client()
    m = Message('DiffieHellman', random.randint(1, 10))
    pub_key = m.obj_to_json()
    client.send_message(pub_key)
