import socket

from utils.diffiehellman import DiffieHellman
from utils.message import Message


class Server:
    def __init__(self, ip='0.0.0.0', port=8888):
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.bind((ip, port))
        self._server_socket.listen(1)
        self._session_key = None
        print(f"Server is up at {ip}:{port}, waiting for the connection...")

    def receive_message(self, text=None):
        global res
        while True:
            conn, addr = self._server_socket.accept()
            print(f'Connected by {addr[0]}:{addr[1]}')
            data = conn.recv(1024)
            if not data: break
            res = self.data_handler(data)
            conn.sendall(res.encode())
            print(f"Message {data.decode()} received, {res} sent. ")
            conn.close()
        return data

    def data_handler(self, data):
        msg = Message(message_json=data.decode())
        if msg.msg_type == 'DiffieHellman':
            dh = DiffieHellman(23, 5)
            dh.generate_key_pair()
            self._session_key = dh.generate_shared_secret(int(msg.message))
            return Message('DiffieHellman', self._session_key).obj_to_json()
        if msg.msg_type == 'hello':
            pass
        if msg.msg_type == 'message':
            pass

    def close_server(self):
        if self._server_socket:
            self._server_socket.close()


if __name__ == "__main__":
    server = Server()
    data = server.receive_message('111')
    print(data)
