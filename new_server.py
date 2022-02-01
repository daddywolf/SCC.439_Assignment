import base64
import json
import socket
import sys
import time
import zlib
from os import urandom

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256, HMAC
from Cryptodome.Util.Padding import pad

from mycryptolib.lancs_DH import DiffieHellman


class Server:
    def __init__(self, local_port):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.bind(('127.0.0.1', int(local_port)))
        self._server.listen(1)

        self._current_state = 'init'
        self._enc_key = b'\xbb\xeb\x8b\x1fP\xdd\x80#\x99s\x08\x81]\xd6\xca3iZv*\xe3\xfe\xe9\xa1V\x8a2M\xbdy\x13p'
        self._iv = b'\xb7N\xa9\xe7\xeau*\x1f\xbc\x86\x0c\xe0xy\xe5\xdc'
        self._hmac_key = b'\x0e\xe6\xcd\xa4vV\xa5\xc8?\xec8\xe2\xffj\xf7k\xef\xd67d\xecJ\xee\xae&:\x11C*\x10N\x1a'
        self._chap_secret = b'\x87\x02x\xa3\xe9\xf1p\x17_`\xcc\xf1\xb9\xaf\xc7LqH\xb1\xdc\xc1\xe9\x9f|\x8f\xc6\x16}*\xf4\xf3&'

    def server_send_message(self, pdu_dict):
        conn, addr = self._server.accept()
        print('Connected by', addr)
        data = conn.recv(1024)
        conn.sendall(json.dumps(pdu_dict).encode())
        conn.close()
        return data.decode()

    def init(self):
        self._server_dh = DiffieHellman()
        self._public_key = self._server_dh.public_key
        print('Server Init Successful.')

    def error(self):
        print('error')

    def dh_2(self):
        # DO DH KEY EXCHANGE
        conn, addr = self._server.accept()
        print('Connected by', addr)
        data = conn.recv(10240)
        dh_1_pdu = json.loads(data.decode())
        username = dh_1_pdu['body']['user']
        print(username)
        client_public_key = int(base64.b64decode(dh_1_pdu['body']['key']).decode())
        dh_2_pdu = {'header': {'msg_type': 'dh_2', 'timestamp': time.time()},
                    'body': {'key': base64.b64encode(str(self._public_key).encode()).decode('utf-8')}}
        dh_2_pdu['header']['crc'] = zlib.crc32(json.dumps(dh_2_pdu).encode('utf-8'))
        conn.sendall(json.dumps(dh_2_pdu).encode())
        self._server_dh.generate_shared_secret(client_public_key)
        # CALCULATE KEYS
        directory = open('../files/directory.json', 'r')
        user_list = json.load(directory)
        user_password = ""
        for i in user_list:
            if i['username'] == username:
                user_password = i['password'].encode()
        hmac = HMAC.new(user_password, self._server_dh.shared_secret_bytes, digestmod=SHA256)
        self._enc_key = hmac.digest()
        hash = SHA256.new()
        hash.update(self._enc_key)
        self._iv = hash.digest()[:16]
        hash.update(self._iv)
        self._hmac_key = hash.digest()
        hash.update(self._hmac_key)
        self._chap_secret = hash.digest()
        print(f"Shared Secret Bytes: {self._server_dh.shared_secret_bytes} \n"
              f"Enc Key :{self._enc_key} \n"
              f"IV: {self._iv} \n"
              f"HMAC Key: {self._hmac_key} \n"
              f"CHAP Secret: {self._chap_secret}")

    def chall(self):
        return self._generate_pdu('chall', urandom(32))

    def resp(self):
        """
        ??? Responses should be a HMAC-SHA256 with the CHAP_SECRET as the password and the random data as the information to be hashed.
        """
        return self._generate_pdu('resp', b'hello world')

    def ack(self):
        return self._generate_pdu('ack', None)

    def nack(self):
        return self._generate_pdu('nack', None)

    def end(self):
        print('end')
        sys.exit(0)

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
    server = Server(local_port=8888)
    server.init()
    dh_2 = server.dh_2()
