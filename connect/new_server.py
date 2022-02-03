import base64
import json
import socket
import sys
import time
import zlib
from os import urandom

from Cryptodome.Hash import SHA256, HMAC

from mycryptolib.lancs_DH import DiffieHellman
from utils.basic_functions import generate_pdu, decrypt_pdu, print_red


class Server:
    def __init__(self, local_port):
        self._current_state = 'init'
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.bind(('127.0.0.1', int(local_port)))
        self._server.listen(1)
        self._random_challenge = None
        self._state_machine = {
            'init': {'init': {'nxt_state': 'dh_2', 'action': self._init}},
            'dh_2': {'ok': {'nxt_state': 'chall', 'action': self._dh_2}},
            'chall': {'ok': {'nxt_state': 'ack_or_nack', 'action': self._chall},
                      'error': {'nxt_state': 'error', 'action': self._error}},
            'ack_or_nack': {'ok': {'nxt_state': 'resp', 'action': self._ack_or_nack},
                            'error': {'nxt_state': 'error', 'action': self._error}},
            'resp': {'ok': {'nxt_state': 'chap_end', 'action': self._resp},
                     'error': {'nxt_state': 'error', 'chall': self._error}},
            'chap_end': {'ok': {'nxt_state': 'text', 'action': self._chap_end}},
            'text': {'ok': {'nxt_state': 'text', 'action': self._text},
                     'error': {'nxt_state': 'error', 'chall': self._error}},
            'error': {'ok': {'nxt_state': 'chall', 'action': self._chall},
                      'error': {'nxt_state': 'error', 'action': self._error}}
        }

    @property
    def server(self):
        return self._server

    def server_send_message(self, pdu_dict):
        conn, addr = self._server.accept()
        data = conn.recv(1024)
        conn.sendall(json.dumps(pdu_dict).encode('utf-8'))
        conn.close()
        return data.decode('utf-8')

    def _init(self):
        self._server_dh = DiffieHellman()
        self._public_key = self._server_dh.public_key
        print('Server Init Successful.')
        return 'ok'

    def _error(self):
        conn, addr = self._server.accept()
        data = conn.recv(1024)
        type, pt = decrypt_pdu(json.loads(data.decode('utf-8')), self._key_dict)
        conn.sendall(json.dumps(generate_pdu('nack', None, self._key_dict)).encode('utf-8'))
        conn.close()

    def _dh_2(self):
        # DO DH KEY EXCHANGE
        conn, addr = self._server.accept()
        print('Connected by', addr)
        data = conn.recv(1024)
        dh_1_pdu = json.loads(data.decode('utf-8'))
        username = dh_1_pdu['body']['user']
        client_public_key = int(base64.b64decode(dh_1_pdu['body']['key']).decode('utf-8'))
        dh_2_pdu = {'header': {'msg_type': 'dh_2', 'timestamp': time.time()},
                    'body': {'key': base64.b64encode(str(self._public_key).encode('utf-8')).decode('utf-8')}}
        dh_2_pdu['header']['crc'] = zlib.crc32(json.dumps(dh_2_pdu).encode('utf-8'))
        conn.sendall(json.dumps(dh_2_pdu).encode('utf-8'))
        conn.close()
        self._server_dh.generate_shared_secret(client_public_key)
        # CALCULATE KEYS
        directory = open('files/directory.json', 'r')
        user_list = json.load(directory)
        for i in user_list:
            if i['username'] == username:
                self._password = i['password']
                self._username = i['username']
        hmac = HMAC.new(self._password.encode('utf-8'), self._server_dh.shared_secret_bytes, digestmod=SHA256)
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
        print('>>>Server Key Generation Successfully')
        return 'ok'

    def _chall(self):
        conn, addr = self._server.accept()
        data = conn.recv(1024)
        type, pt = decrypt_pdu(json.loads(data.decode('utf-8')), self._key_dict)
        self._random_challenge = urandom(32)
        conn.sendall(json.dumps(generate_pdu('chall', self._random_challenge, self._key_dict)).encode('utf-8'))
        conn.close()
        return 'ok'

    def _ack_or_nack(self):
        conn, addr = self._server.accept()
        data = conn.recv(1024)
        type, pt = decrypt_pdu(json.loads(data.decode('utf-8')), self._key_dict)
        ct_HMAC = HMAC.new(self._chap_secret, self._random_challenge, digestmod=SHA256)
        try:
            ct_HMAC.verify(pt)
            conn.sendall(json.dumps(generate_pdu('ack', None, self._key_dict)).encode('utf-8'))
            conn.close()
            print('>>>Single CHAP OK')
            return 'ok'
        except Exception as e:
            conn.sendall(json.dumps(generate_pdu('nack', None, self._key_dict)).encode('utf-8'))
            conn.close()
            print('>>>Single CHAP ERROR')
            return 'error'

    def _resp(self):
        conn, addr = self._server.accept()
        data = conn.recv(1024)
        type, pt = decrypt_pdu(json.loads(data.decode('utf-8')), self._key_dict)
        ct_HMAC = HMAC.new(self._chap_secret, pt, digestmod=SHA256)
        conn.sendall(json.dumps(generate_pdu('resp', ct_HMAC.digest(), self._key_dict)).encode('utf-8'))
        conn.close()
        return 'ok'

    def _chap_end(self):
        conn, addr = self._server.accept()
        data = conn.recv(1024)
        type, pt = decrypt_pdu(json.loads(data.decode('utf-8')), self._key_dict)
        if type == 'ack':
            conn.sendall(json.dumps(generate_pdu('ack', None, self._key_dict)).encode('utf-8'))
            print('>>>Mutual CHAP OK')
            print('>>>Receiving messages from client...')
            return 'ok'
        if type == 'nack':
            print('>>>Mutual CHAP ERROR')
            return 'error'
        conn.close()

    def _text(self):
        conn, addr = self._server.accept()
        data = conn.recv(1024)
        type, pt = decrypt_pdu(json.loads(data.decode('utf-8')), self._key_dict)
        if pt.decode('utf-8') == 'close()':
            conn.close()
            self._server.close()
            print(">>>Bye")
            sys.exit(0)
        else:
            print_red(f"\n<{self._username}> on <{addr[0]}:{addr[1]}> says: {pt.decode('utf-8')}")
        conn.sendall(json.dumps(generate_pdu('ack', None, self._key_dict)).encode('utf-8'))
        conn.close()
        return 'ok'

    def event_handler(self, event):
        if self._current_state not in self._state_machine.keys():
            raise Exception(f'current state not in state list: {self._current_state}')
        nxt_state = self._state_machine[self._current_state][event]['nxt_state']
        action = self._state_machine[self._current_state][event]['action']
        ret = None
        if action is not None:
            ret = action()
        if ret == 'ok':
            self._current_state = nxt_state
        return ret


if __name__ == "__main__":
    # Init Server
    server = Server(local_port=8888)
    status = server.event_handler('init')
    retry = 0
    while status:
        if status == 'ok':
            status = server.event_handler(status)
        if status == 'error':
            retry += 1
            print(retry)
            if retry >= 3:
                sys.exit()
            print('error handler')
            status = server.event_handler('error')
    # server.init()
    # dh_2 = server.dh_2()
    # server.chall()
    # ack = server.ack_or_nack()
    # server.resp()
    # server.chap_end()
