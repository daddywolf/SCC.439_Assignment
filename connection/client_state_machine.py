import base64
import json
import time
import zlib
from os import urandom

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256, HMAC
from Cryptodome.Util.Padding import pad

from mycryptolib.lancs_DH import DiffieHellman


class ClientStateMachine:
    def __init__(self):
        # TODO 要思考一下这里的Error构造
        self._state_machine = {
            'init': {'init': {'nxt_state': 'dh_1', 'action': self._init},
                     'error': {'nxt_state': 'dh_1', 'action': self._error}},
            'dh_1': {'ok': {'nxt_state': 'hello', 'action': self._dh_1},
                     'error': {'nxt_state': 'init', 'action': self._error}},
            'hello': {'ok': {'nxt_state': 'resp', 'action': self._hello},
                      'error': {'nxt_state': 'dh_1', 'action': self._error}},
            'resp': {'ok': {'nxt_state': 'chall', 'action': self._resp},
                     'error': {'nxt_state': 'dh_1', 'action': self._error}},
            'chall': {'ok': {'nxt_state': 'ack', 'action': self._chall},
                      'error': {'nxt_state': 'dh_1', 'action': self._error}},
            'ack': {'ok': {'nxt_state': 'text', 'action': self._ack},
                    'error': {'nxt_state': 'dh_1', 'action': self._error}},
            'text': {'ok': {'nxt_state': 'text', 'action': self._text},
                     'error': {'nxt_state': 'dh_1', 'action': self._error}}
        }
        self._current_state = 'init'
        self._enc_key = b'\xbb\xeb\x8b\x1fP\xdd\x80#\x99s\x08\x81]\xd6\xca3iZv*\xe3\xfe\xe9\xa1V\x8a2M\xbdy\x13p'
        self._iv = b'\xb7N\xa9\xe7\xeau*\x1f\xbc\x86\x0c\xe0xy\xe5\xdc'
        self._hmac_key = b'\x0e\xe6\xcd\xa4vV\xa5\xc8?\xec8\xe2\xffj\xf7k\xef\xd67d\xecJ\xee\xae&:\x11C*\x10N\x1a'
        self._chap_secret = b'\x87\x02x\xa3\xe9\xf1p\x17_`\xcc\xf1\xb9\xaf\xc7LqH\xb1\xdc\xc1\xe9\x9f|\x8f\xc6\x16}*\xf4\xf3&'

    def _init(self):
        client_dh = DiffieHellman()
        self._public_key = client_dh.public_key_bytes
        print('Client Public Key Success...')
        return {}

    # TODO 要好好想想这里如何设计
    def _error(self):
        print('error')

    def _dh_1(self):
        pdu = {'header': {'msg_type': 'dh_1', 'timestamp': time.time()},
               'body': {'key': base64.b64encode(self._public_key).decode('utf-8'),
                        'user': 'username'}}  # utf-8 encode username?
        pdu['header']['crc'] = zlib.crc32(json.dumps(pdu).encode('utf-8'))
        return json.dumps(pdu)

    def _hello(self):
        pdu = self.generate_pdu('hello', None)
        return pdu

    def _resp(self):
        """
        ??? Responses should be a HMAC-SHA256 with the CHAP_SECRET as the password and the random data as the information to be hashed.
        """
        pdu = self.generate_pdu('resp', b'hello world')
        return pdu

    def _chall(self):
        pdu = self.generate_pdu('chall', urandom(32))
        return pdu

    def _ack(self):
        pdu = self.generate_pdu('ack', None)
        return pdu

    def _text(self):
        pdu = self.generate_pdu('text', 'message'.encode('utf-8'))
        return pdu

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

    def generate_pdu(self, state, data):
        cipher = AES.new(self._enc_key, AES.MODE_CBC, self._iv)
        if data:
            ct_bytes = cipher.encrypt(pad(data, AES.block_size))
            pdu = {'header': {'msg_type': state, 'timestamp': time.time()},
                   'body': base64.b64encode(ct_bytes).decode('utf-8'),
                   'security': {'hmac': {'type': 'SHA256'}, 'enc_type': 'AES256-CBC'}}
        else:
            pdu = {'header': {'msg_type': state, 'timestamp': time.time()},
                   'body': None, 'security': {'hmac': {'type': 'SHA256'}}}
        pdu['security']['hmac']['val'] = base64.b64encode(HMAC.new(self._hmac_key, json.dumps(pdu).encode('utf-8'),
                                                                   digestmod=SHA256).digest()).decode()
        pdu['header']['crc'] = zlib.crc32(json.dumps(pdu).encode('utf-8'))
        return json.dumps(pdu)


if __name__ == "__main__":
    csm = ClientStateMachine()
    event = 'init'
    while True:
        time.sleep(1)
        pdu = csm.event_handler(event)
        print(pdu)
        event = 'ok'
