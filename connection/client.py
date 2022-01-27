import random
import socket

from utils.message import Message


class Client:
    def __init__(self, ip='0.0.0.0', port=8888):
        self._client_socket = None
        self._ip = ip
        self._port = port
        self._session_key = None

    def send_message(self, text=None):
        self._client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._client_socket.setblocking(True)
        self._client_socket.connect((self._ip, self._port))
        print(f"Client is connected at {self._ip}:{self._port}")
        self._client_socket.sendall(text.encode())
        data = self._client_socket.recv(1024)
        self.data_handler(data)
        print(f"Message {str(text).encode()} sent. Response: {data}")
        self._client_socket.close()
        return data

    def data_handler(self, data):
        msg = Message(message_json=data.decode())
        if msg.msg_type == 'DiffieHellman':
            self._session_key = int(msg.message)
            print(f"DiffieHellman Key Exchange Successful. Shared Session Key: {self._session_key}")
        if msg.msg_type == 'challenge':
            print(f"Challenge received. {msg.message + hex(self._session_key)}")


if __name__ == "__main__":
    client = Client()
    # Exchange Shared Key
    pub_key = Message('DiffieHellman', random.randint(1, 10)).obj_to_json()
    client.send_message(pub_key)
    # CHAP - Hello
    hello = Message('hello', '').obj_to_json()
    client.send_message(hello)
