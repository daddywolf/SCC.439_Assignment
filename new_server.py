import base64
import json
import socket
import time
import zlib
from os import urandom

from Cryptodome.Hash import SHA256, HMAC

from mycryptolib.lancs_DH import DiffieHellman
from utils.basic_functions import generate_pdu, decrypt_pdu


class Server:
    def __init__(self, local_port):
        self._current_state = 'init'
        self._random_challenge = None
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.bind(('127.0.0.1', int(local_port)))
        self._server.listen(1)
        self._state_machine = {
            'init': {'init': {'nxt_state': 'dh_2', 'action': self._init},
                     'error': {'nxt_state': 'end', 'action': self._error}},
            'dh_2': {'ok': {'nxt_state': 'chall', 'action': self._dh_2},
                     'error': {'nxt_state': 'end', 'action': self._error}},
            'chall': {'ok': {'nxt_state': 'ack_or_nack', 'action': self._chall},
                      'error': {'nxt_state': 'chall', 'action': self._error}},
            'ack_or_nack': {'ok': {'nxt_state': 'resp', 'action': self._ack_or_nack},
                            'error': {'nxt_state': 'chall', 'action': self._error}},
            'resp': {'ok': {'nxt_state': 'chap_end', 'action': self._resp},
                     'error': {'nxt_state': 'end', 'chall': self._error}},
            'chap_end': {'ok': {'nxt_state': 'init', 'action': self._chap_end}}
        }

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
        return "ok"

    def _error(self):
        print('error')

    def _dh_2(self):
        # DO DH KEY EXCHANGE
        conn, addr = self._server.accept()
        print('Connected by', addr)
        data = conn.recv(1024)
        dh_1_pdu = json.loads(data.decode('utf-8'))
        username = dh_1_pdu['body']['user']
        print(username)
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
        user_password = ""
        for i in user_list:
            if i['username'] == username:
                user_password = i['password'].encode('utf-8')
        hmac = HMAC.new(user_password, self._server_dh.shared_secret_bytes, digestmod=SHA256)
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
        return "ok"

    def _chall(self):
        conn, addr = self._server.accept()
        data = conn.recv(1024)
        type, pt = decrypt_pdu(json.loads(data.decode('utf-8')), self._key_dict)
        self._random_challenge = urandom(32)
        conn.sendall(json.dumps(generate_pdu('chall', self._random_challenge, self._key_dict)).encode('utf-8'))
        conn.close()
        return "ok"

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
            return "ok"
        except Exception as e:
            conn.sendall(json.dumps(generate_pdu('nack', None, self._key_dict)).encode('utf-8'))
            conn.close()
            print('>>>Single CHAP ERROR')
            return "error"

    def _resp(self):
        conn, addr = self._server.accept()
        data = conn.recv(1024)
        type, pt = decrypt_pdu(json.loads(data.decode('utf-8')), self._key_dict)
        ct_HMAC = HMAC.new(self._chap_secret, pt, digestmod=SHA256)
        conn.sendall(json.dumps(generate_pdu('resp', ct_HMAC.digest(), self._key_dict)).encode('utf-8'))
        conn.close()
        return "ok"

    def _chap_end(self):
        conn, addr = self._server.accept()
        data = conn.recv(1024)
        type, pt = decrypt_pdu(json.loads(data.decode('utf-8')), self._key_dict)
        if type == 'ack':
            conn.sendall(json.dumps(generate_pdu('ack', None, self._key_dict)).encode('utf-8'))
            print('>>>Mutual CHAP OK')
            return "Mutual CHAP OK"
        if type == 'nack':
            print('>>>Mutual CHAP ERROR')
            return "error"
        conn.close()

    def event_handler(self, event):
        if self._current_state not in self._state_machine.keys():
            raise Exception(f'current state not in state list {self._current_state}')
        nxt_state = self._state_machine[self._current_state][event]['nxt_state']
        action = self._state_machine[self._current_state][event]['action']
        ret = None
        if action is not None:
            ret = action()
        self._current_state = nxt_state
        return ret


if __name__ == "__main__":
    # Init Server
    server = Server(local_port=8888)
    status = server.event_handler('init')
    while status != 'error':
        flag = server.event_handler(status)  # dh_2
        if flag == 'Mutual CHAP OK':
            break
    # server.init()
    # dh_2 = server.dh_2()
    # server.chall()
    # ack = server.ack_or_nack()
    # server.resp()
    # server.chap_end()
