import base64
import json
import socket
import sys
import time
import zlib
from os import urandom

from Cryptodome.Hash import SHA256, HMAC

from mycryptolib.directory_protection import decrypt_file_to_user_json
from mycryptolib.lancs_DH import DiffieHellman
from utils.basic_functions import generate_pdu, decrypt_pdu, print_red


class Server:
    def __init__(self, user):
        """
        Constructor. Initializes all required variables.
        :param user: The user dict you selected to receive messages.
        """
        self._local_ip = user['ip']
        self._local_port = user['port']
        self._user = user
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.bind((self._local_ip, int(self._local_port)))
        self._server.listen(1)
        self._random_challenge = None
        # Implementation of finite state machines.
        self._current_state = 'init'
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
    def server(self):  # getter of self._server
        return self._server

    def server_send_message(self, pdu_dict):
        """
        This function receives the PDU dictionary from client and get the PDU dictionary back.
        :param pdu_dict: PDU dictionary
        :return: Decoded client message.
        """
        conn, addr = self._server.accept()
        data = conn.recv(1024)
        conn.sendall(json.dumps(pdu_dict).encode('utf-8'))
        conn.close()
        return data.decode('utf-8')

    def _init(self):
        """
        This function generate the DiffieHellman object. So that the DiffieHellman key pair can be get.
        e.g.: self._server_dh.public_key
        :return: This function executed successfully.
        """
        self._server_dh = DiffieHellman()
        print('Server Init Successful.')
        return 'ok'

    def _error(self):
        """
        This function only be used when error exists. It will send an 'nack' to the client. Finally close the connection.
        """
        conn, addr = self._server.accept()
        data = conn.recv(1024)
        type, pt = decrypt_pdu(json.loads(data.decode('utf-8')), self._key_dict)
        conn.sendall(json.dumps(generate_pdu('nack', None, self._key_dict)).encode('utf-8'))
        conn.close()

    def _dh_2(self):
        """ STEP.2: DiffieHellman
        Do DiffieHellman Key Exchange Step1 (Server -> Client)
        :return: This function executed successfully.
        """
        # Get the client-side PDU and get the client-side public key and username.
        conn, addr = self._server.accept()
        print('Connected by', addr)
        data = conn.recv(1024)
        dh_1_pdu = json.loads(data.decode('utf-8'))
        username = dh_1_pdu['body']['user']
        client_public_key = int(base64.b64decode(dh_1_pdu['body']['key']).decode('utf-8'))
        # Constructing server PDU and generating CRC, then send it
        dh_2_pdu = {'header': {'msg_type': 'dh_2', 'timestamp': time.time()},
                    'body': {'key': base64.b64encode(str(self._server_dh.public_key).encode('utf-8')).decode('utf-8')}}
        dh_2_pdu['header']['crc'] = zlib.crc32(json.dumps(dh_2_pdu).encode('utf-8'))
        conn.sendall(json.dumps(dh_2_pdu).encode('utf-8'))
        conn.close()
        # Perform DiffieHellman key exchange
        self._server_dh.generate_shared_secret(client_public_key)
        directory_dict = decrypt_file_to_user_json('encrypted_directory.bin')
        for i in directory_dict:
            if i['username'] == username:
                self._password = i['password']
                self._username = i['username']
        # Save the generated key to the class variable. self._key_dict will be used to generate PDU and decrypt the PDU
        hmac = HMAC.new(self._password.encode('utf-8'), self._server_dh.shared_secret_bytes, digestmod=SHA256)
        self._enc_key = hmac.digest()
        hash = SHA256.new()
        hash.update(self._enc_key)
        self._iv = hash.digest()[:16]
        hash.update(self._iv)
        self._hmac_key = hash.digest()
        hash.update(self._hmac_key)
        self._chap_secret = hash.digest()
        self._key_dict = {  # This dict is used to generate and decrypt the PDU. see utils/basic_functions.py
            'iv': self._iv,
            'enc_key': self._enc_key,
            'hmac_key': self._hmac_key,
            'chap_secret': self._chap_secret
        }
        print('>>>Client Key Chain Generation Successfully')
        return 'ok'

    def _chall(self):
        """ STEP.4: Single CHAP
        Get the 'hello' message and generate a random bytes challenge value then send it back to client
        :return: This function executed successfully.
        """
        conn, addr = self._server.accept()
        data = conn.recv(1024)
        type, pt = decrypt_pdu(json.loads(data.decode('utf-8')), self._key_dict)
        self._random_challenge = urandom(32)
        conn.sendall(json.dumps(generate_pdu('chall', self._random_challenge, self._key_dict)).encode('utf-8'))
        conn.close()
        return 'ok'

    def _ack_or_nack(self):
        """ STEP.6: Single CHAP
        Receive the challenge response from the client and verify it.
        If verify correct --> send ACK back
        If verify incorrect --> send NACK back
        :return: This function executed successfully or not.
        """
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
        """ STEP.8: Mutual CHAP
        Response to the challenge message using HMAC. Send it back then get the ACK or NACK from client
        :return: This function executed successfully.
        """
        conn, addr = self._server.accept()
        data = conn.recv(1024)
        type, pt = decrypt_pdu(json.loads(data.decode('utf-8')), self._key_dict)
        ct_HMAC = HMAC.new(self._chap_secret, pt, digestmod=SHA256)
        conn.sendall(json.dumps(generate_pdu('resp', ct_HMAC.digest(), self._key_dict)).encode('utf-8'))
        conn.close()
        return 'ok'

    def _chap_end(self):
        """ STEP.10: Mutual CHAP
        Get the ACK or NACK from the client to confirm the Mutual CHAP is successful or not.
        :return: This function executed successfully or not.
        """
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
        """
        receive messages from the client and decrypt the message and show it to the user. if 'close()' received, to shut the server down.
        :return: This function executed successfully or not.
        """
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
        """
        Event manipulation functions for finite state machines.
        :param event: 'ok' or 'text' or 'error'
        :return: the function outcome
        """
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


'''
# Testing functions. It CAN be used however you don't have to. I used this to test my code before I write the main.py
if __name__ == "__main__":
    server = Server({'ip': '0.0.0.0', 'port': 8888})
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
'''
