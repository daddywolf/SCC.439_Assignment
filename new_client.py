import base64
import json
import socket
import time
import zlib
from os import urandom

from Cryptodome.Hash import SHA256, HMAC

from mycryptolib.lancs_DH import DiffieHellman
from utils.basic_functions import input_directory, select_user_from_table, generate_pdu, decrypt_pdu


class Client:
    def __init__(self, remote_ip, remote_port):
        self._rempte_ip = remote_ip
        self._remote_port = remote_port

    def client_send_message(self, pdu_dict):
        self._client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._client.connect((self._rempte_ip, int(self._remote_port)))
        self._current_state = 'init'
        self._client.sendall(json.dumps(pdu_dict).encode())
        data = self._client.recv(1024)
        self._client.close()
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
        self._key_dict = {
            'iv': self._iv,
            'enc_key': self._enc_key,
            'hmac_key': self._hmac_key,
            'chap_secret': self._chap_secret
        }
        print('Key Generation Successfully')
        return True

    def hello(self):
        ret = self.client_send_message(generate_pdu('hello', None, self._key_dict))
        print(ret)
        pdu_dict = json.loads(ret)
        type, pt = decrypt_pdu(pdu_dict, self._key_dict)
        print(f"type: {type}, pt: {pt}")
        return

    def resp(self):
        """
        ??? Responses should be a HMAC-SHA256 with the CHAP_SECRET as the password and the random data as the information to be hashed.
        """
        pdu = generate_pdu('resp', b'hello world', self._key_dict)
        return pdu

    def chall(self):
        return generate_pdu('chall', urandom(32), self._key_dict)

    def ack(self):
        return generate_pdu('ack', None, self._key_dict)

    def text(self):
        return generate_pdu('text', 'message'.encode('utf-8'), self._key_dict)


if __name__ == "__main__":
    # Pick User
    directory_dict = input_directory('directory.json')
    user = select_user_from_table(directory_dict)
    # Init Client
    client = Client(remote_ip='0.0.0.0', remote_port=8888)
    client.init()
    dh_1 = client.dh_1(user)
    client.hello()
