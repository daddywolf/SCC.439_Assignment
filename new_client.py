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
        self._current_state = 'init'
        self._random_challange = None
        self._rempte_ip = remote_ip
        self._remote_port = remote_port
        self._state_machine = {
            'init': {'init': {'nxt_state': 'dh_1', 'action': self._init},
                     'error': {'nxt_state': 'dh_1', 'action': self._error}},
            'dh_1': {'ok': {'nxt_state': 'hello', 'action': self._dh_1},
                     'error': {'nxt_state': 'init', 'action': self._error}},
            'hello': {'ok': {'nxt_state': 'resp', 'action': self._hello},
                      'error': {'nxt_state': 'hello', 'action': self._error}},
            'resp': {'ok': {'nxt_state': 'chall', 'action': self._resp},
                     'error': {'nxt_state': 'hello', 'action': self._error}},
            'chall': {'ok': {'nxt_state': 'ack_or_nack', 'action': self._chall},
                      'error': {'nxt_state': 'hello', 'action': self._error}},
            'ack_or_nack': {'ok': {'nxt_state': 'text', 'action': self._ack_or_nack},
                            'error': {'nxt_state': 'hello', 'action': self._error}},
            'text': {'ok': {'nxt_state': 'text', 'action': self._text},
                     'error': {'nxt_state': 'hello', 'action': self._error}}
        }

    def client_send_message(self, pdu_dict):
        self._client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._client.connect((self._rempte_ip, int(self._remote_port)))
        self._client.sendall(json.dumps(pdu_dict).encode())
        data = self._client.recv(1024)
        self._client.close()
        return data.decode()

    def _init(self):
        self._client_dh = DiffieHellman()
        self._public_key = self._client_dh.public_key
        print('Client Init Successful.')
        return True

    # TODO 要好好想想这里如何设计
    def _error(self):
        print('error')

    def _dh_1(self, user):
        # DO DH KEY EXCHANGE
        dh_1_pdu = {'header': {'msg_type': 'dh_1', 'timestamp': time.time()},
                    'body': {'key': base64.b64encode(str(self._public_key).encode()).decode('utf-8'),
                             'user': user[0]['username']}}
        dh_1_pdu['header']['crc'] = zlib.crc32(json.dumps(dh_1_pdu).encode('utf-8'))
        dh_2_pdu = json.loads(self.client_send_message(dh_1_pdu))
        server_public_key = int(base64.b64decode(dh_2_pdu['body']['key']).decode())
        self._client_dh.generate_shared_secret(server_public_key)
        # CALCULATE KEYS
        user_password = user[0]['password'].encode()
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
        print('>>>Client Key Generation Successfully')
        return True

    def _hello(self):
        pdu = generate_pdu('hello', None, self._key_dict)
        ret = self.client_send_message(pdu)
        pdu_dict = json.loads(ret)
        type, ran_chall = decrypt_pdu(pdu_dict, self._key_dict)
        return ran_chall

    def _resp(self, ran_chall):
        ct_HMAC = HMAC.new(self._chap_secret, ran_chall[0], digestmod=SHA256)
        pdu = generate_pdu('resp', ct_HMAC.digest(), self._key_dict)
        ret = self.client_send_message(pdu)
        pdu_dict = json.loads(ret)
        type, pt = decrypt_pdu(pdu_dict, self._key_dict)
        if type == 'ack':
            print('>>>Single CHAP OK')
            return True
        if type == 'nack':
            print('>>>Single CHAP ERROR')
            return False

    def _chall(self):
        self._random_challange = urandom(32)
        pdu = generate_pdu('chall', self._random_challange, self._key_dict)
        ret = self.client_send_message(pdu)
        pdu_dict = json.loads(ret)
        type, pt = decrypt_pdu(pdu_dict, self._key_dict)
        return pt

    def _ack_or_nack(self, hmac):
        ct_HMAC = HMAC.new(self._chap_secret, self._random_challange, digestmod=SHA256)
        try:
            ct_HMAC.verify(hmac[0])
            pdu = generate_pdu('ack', None, self._key_dict)
        except Exception as e:
            pdu = generate_pdu('nack', None, self._key_dict)
        ret = self.client_send_message(pdu)
        pdu_dict = json.loads(ret)
        type, pt = decrypt_pdu(pdu_dict, self._key_dict)
        if type == 'ack':
            print('>>>Mutual CHAP OK')
            return True
        if type == 'nack':
            print('>>>Mutual CHAP ERROR')
            return False

    def _text(self):
        # TODO
        return generate_pdu('text', 'message'.encode('utf-8'), self._key_dict)

    def event_handler(self, event, *args):
        if self._current_state not in self._state_machine.keys():
            raise Exception(f'current state not in state list {self._current_state}')
        nxt_state = self._state_machine[self._current_state][event]['nxt_state']
        action = self._state_machine[self._current_state][event]['action']
        if not args:
            ret = action()
        else:
            ret = action(args)
        self._current_state = nxt_state
        return ret


if __name__ == "__main__":
    # Pick User
    directory_dict = input_directory('directory.json')
    user = select_user_from_table(directory_dict)
    # Init Client
    client = Client(remote_ip='0.0.0.0', remote_port=8888)
    client.event_handler('init')
    flag = client.event_handler('ok', user)  # dh_1
    ran_chall = client.event_handler('ok')  # hello
    flag = client.event_handler('ok', ran_chall)  # resp
    hmac = client.event_handler('ok')  # chall
    flag = client.event_handler('ok', hmac)  # ack_or_nack
    # client.init()
    # dh_1 = client.dh_1(user)
    # ran_chall = client.hello()
    # client.resp(ran_chall)
    # hmac = client.chall()
    # client.ack_or_nack(hmac)
