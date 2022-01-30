import base64
import json
import sys
import time
import zlib


class ClientStateMachine:
    def __init__(self):
        self._state_machine = {
            'init': {'init': {'nxt_state': 'dh_1', 'action': self._init},
                     'error': {'nxt_state': 'dh_1', 'action': self._error}},
            'dh_1': {'ok': {'nxt_state': 'hello', 'action': self._dh_1},
                     'error': {'nxt_state': 'dh_1', 'action': self._error}},
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

    def _init(self):
        print('init')

    def _error(self):
        print('error')

    def _dh_1(self):
        pdu = {'header': {'msg_type': 'dh_1', 'timestamp': int(time.time())},
               'body': {'key': 'a_public_key', 'user': 'username'}}
        pdu['header']['crc'] = zlib.crc32(json.dumps(pdu).encode())
        print(pdu)

    def _hello(self):
        pdu = {'header': {'msg_type': 'hello', 'timestamp': int(time.time())}, 'body': None}
        pdu['security'] = {'hmac': {'type': 'SHA256', 'val': 'hmac_of_pdu'}}
        pdu['header']['crc'] = zlib.crc32(json.dumps(pdu).encode())
        print(pdu)

    def _resp(self):
        pdu = {'header': {'msg_type': 'resp', 'timestamp': int(time.time())}, 'body': 'resp_val'}
        pdu['security'] = {'hmac': {'type': 'SHA256', 'val': 'hmac_of_pdu'}}
        pdu['header']['crc'] = zlib.crc32(json.dumps(pdu).encode())
        print(pdu)

    def _chall(self):
        pdu = {'header': {'msg_type': 'chall', 'timestamp': int(time.time())}, 'body': 'chall_val'}
        pdu['security'] = {'hmac': {'type': 'SHA256', 'val': 'hmac_of_pdu'}}
        pdu['header']['crc'] = zlib.crc32(json.dumps(pdu).encode())
        print(pdu)

    def _ack(self):
        pdu = {'header': {'msg_type': 'ack', 'timestamp': int(time.time())}, 'body': None}
        pdu['security'] = {'hmac': {'type': 'SHA256', 'val': 'hmac_of_pdu'}}
        pdu['header']['crc'] = zlib.crc32(json.dumps(pdu).encode())
        print(pdu)

    def _text(self):
        pdu = {'header': {'msg_type': 'text', 'timestamp': int(time.time())},
               'body': base64.b64encode('message'.encode()).decode()}
        pdu['security'] = {'hmac': {'type': 'SHA256', 'val': 'hmac_of_pdu'}}
        pdu['header']['crc'] = zlib.crc32(json.dumps(pdu).encode())
        print(pdu)

    def event_handler(self, event):
        if self._current_state not in self._state_machine.keys():
            raise Exception(f'current state not in state list {self._current_state}')
        nxt_state = self._state_machine[self._current_state][event]['nxt_state']
        action = self._state_machine[self._current_state][event]['action']
        if action is not None:
            action()
        self._current_state = nxt_state
        return self._current_state


class ServerStateMachine:
    def __init__(self):
        self._state_machine = {
            'init': {'init': {'nxt_state': 'dh_2', 'action': self._init},
                     'error': {'nxt_state': 'end', 'action': self._error}},
            'dh_2': {'ok': {'nxt_state': 'chall', 'action': self._dh_2},
                     'error': {'nxt_state': 'end', 'action': self._error}},
            'chall': {'ok': {'nxt_state': 'ack', 'action': self._ack},
                      'error': {'nxt_state': 'nack', 'action': self._nack}},
            'ack': {'ok': {'nxt_state': 'end', 'action': self._resp},
                    'error': {'nxt_state': 'end', 'action': self._error}},
            'resp': {'ok': {'nxt_state': 'ack', 'action': self._ack},
                     'error': {'nxt_state': 'end', 'action': self._nack}},
            'nack': {'ok': {'nxt_state': 'end', 'action': self._nack}},
            'end': {'ok': {'nxt_state': 'init', 'action': self._end}}
        }
        self._current_state = 'init'

    def _init(self):
        print('init')

    def _error(self):
        print('error')

    def _dh_2(self):
        pdu = {'header': {'msg_type': 'dh_2', 'timestamp': int(time.time())},
               'body': {'key': 'b_public_key'}}
        pdu['header']['crc'] = zlib.crc32(json.dumps(pdu).encode())
        print(pdu)

    def _chall(self):
        pdu = {'header': {'msg_type': 'chall', 'timestamp': int(time.time())}, 'body': 'chall_val'}
        pdu['security'] = {'hmac': {'type': 'SHA256', 'val': 'hmac_of_pdu'}}
        pdu['header']['crc'] = zlib.crc32(json.dumps(pdu).encode())
        print(pdu)

    def _resp(self):
        pdu = {'header': {'msg_type': 'resp', 'timestamp': int(time.time())}, 'body': 'resp_val'}
        pdu['security'] = {'hmac': {'type': 'SHA256', 'val': 'hmac_of_pdu'}}
        pdu['header']['crc'] = zlib.crc32(json.dumps(pdu).encode())
        print(pdu)

    def _ack(self):
        pdu = {'header': {'msg_type': 'ack', 'timestamp': int(time.time())}, 'body': None}
        pdu['security'] = {'hmac': {'type': 'SHA256', 'val': 'hmac_of_pdu'}}
        pdu['header']['crc'] = zlib.crc32(json.dumps(pdu).encode())
        print(pdu)

    def _nack(self):
        pdu = {'header': {'msg_type': 'nack', 'timestamp': int(time.time())}, 'body': None}
        pdu['security'] = {'hmac': {'type': 'SHA256', 'val': 'hmac_of_pdu'}}
        pdu['header']['crc'] = zlib.crc32(json.dumps(pdu).encode())
        print(pdu)

    def _end(self):
        print('end')
        sys.exit(0)

    def event_handler(self, event):
        if self._current_state not in self._state_machine.keys():
            raise Exception(f'current state not in state list {self._current_state}')
        nxt_state = self._state_machine[self._current_state][event]['nxt_state']
        action = self._state_machine[self._current_state][event]['action']
        if action is not None:
            action()
        self._current_state = nxt_state
        return self._current_state


if __name__ == "__main__":
    # csm = ClientStateMachine()
    #
    # event = 'init'
    # while True:
    #     time.sleep(1)
    #     c_state = csm.event_handler(event)
    #     print(f'now in: {c_state}')
    #     event = 'ok'

    ssm = ServerStateMachine()
    event = 'init'
    while True:
        time.sleep(1)
        c_state = ssm.event_handler(event)
        print(f'now in: {c_state}')
        event = 'ok'
