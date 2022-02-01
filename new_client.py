import base64
import json
import socket
import time
import zlib
from os import urandom

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256, HMAC
from Cryptodome.Util.Padding import pad

from mycryptolib.lancs_DH import DiffieHellman
from utils.basic_functions import input_directory, select_user_from_table


class Client:
    def __init__(self, remote_ip, remote_port):
        self._client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._client.connect((remote_ip, int(remote_port)))
        self._current_state = 'init'

    def client_send_message(self, pdu_dict):
        self._client.sendall(json.dumps(pdu_dict).encode())
        data = self._client.recv(10240)
        return data.decode()

    def init(self):
        self._client_dh = DiffieHellman()
        self._public_key = self._client_dh.public_key
        print('Client Init Successful.')

    # TODO 要好好想想这里如何设计
    def error(self):
        print('error')

    def dh_1(self, user):
        # DO DH KEY EXCHANGE
        dh_1_pdu = {'header': {'msg_type': 'dh_1', 'timestamp': time.time()},
                    'body': {'key': base64.b64encode(str(self._public_key).encode()).decode('utf-8'),
                             'user': user['username']}}
        dh_1_pdu['header']['crc'] = zlib.crc32(json.dumps(dh_1_pdu).encode('utf-8'))
        dh_2_pdu = json.loads(self.client_send_message(dh_1_pdu))
        server_public_key = int(base64.b64decode(dh_2_pdu['body']['key']).decode())
        self._client_dh.generate_shared_secret(server_public_key)
        # CALCULATE KEYS
        user_password = user['password'].encode()
        hmac = HMAC.new(user_password, self._client_dh.shared_secret_bytes, digestmod=SHA256)
        self._enc_key = hmac.digest()
        hash = SHA256.new()
        hash.update(self._enc_key)
        self._iv = hash.digest()[:16]
        hash.update(self._iv)
        self._hmac_key = hash.digest()
        hash.update(self._hmac_key)
        self._chap_secret = hash.digest()
        print(f"Shared Secret Bytes: {self._client_dh.shared_secret_bytes} \n"
              f"Enc Key :{self._enc_key} \n"
              f"IV: {self._iv} \n"
              f"HMAC Key: {self._hmac_key} \n"
              f"CHAP Secret: {self._chap_secret}")

    def hello(self):
        return self._generate_pdu('hello', None)

    def resp(self):
        """
        ??? Responses should be a HMAC-SHA256 with the CHAP_SECRET as the password and the random data as the information to be hashed.
        """
        pdu = self._generate_pdu('resp', b'hello world')
        return pdu

    def chall(self):
        return self._generate_pdu('chall', urandom(32))

    def ack(self):
        return self._generate_pdu('ack', None)

    def text(self):
        return self._generate_pdu('text', 'message'.encode('utf-8'))

    def _generate_pdu(self, state, data):
        body = None
        if data:
            cipher = AES.new(self._enc_key, AES.MODE_CBC, self._iv)
            ct_bytes = cipher.encrypt(pad(data, AES.block_size))
            body = base64.b64encode(ct_bytes).decode('utf-8')
        pdu = {'header': {'msg_type': state, 'timestamp': time.time(), 'crc': 0x00}, 'body': body,
               'security': {'hmac': {'type': 'SHA256', 'val': 0x00}, 'enc_type': 'AES256-CBC'}}
        pdu['security']['hmac']['val'] = base64.b64encode(HMAC.new(self._hmac_key, json.dumps(pdu).encode('utf-8'),
                                                                   digestmod=SHA256).digest()).decode()
        pdu['header']['crc'] = zlib.crc32(json.dumps(pdu).encode('utf-8'))
        return pdu


if __name__ == "__main__":
    directory_dict = input_directory('directory.json')
    user = select_user_from_table(directory_dict)
    print(user)
    user = {"username": "jiangzhipeng", "password": "666666", "port": "8888", "ip": "127.0.0.1"}
    client = Client(remote_ip='0.0.0.0', remote_port=8888)
    client.init()
    dh_1 = client.dh_1(user)
