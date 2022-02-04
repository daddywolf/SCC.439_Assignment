import base64
import json
import socket
import time
import zlib
from os import urandom

from Cryptodome.Hash import SHA256, HMAC

from mycryptolib.lancs_DH import DiffieHellman
from utils.basic_functions import generate_pdu, parse_pdu


class Client:
    def __init__(self, user):
        """
        Constructor. Initializes all required variables.
        :param user: The user dict you selected to send messages to.
        """
        self._remote_ip = user['ip']  # Get the ip from the user dict to send messages
        self._remote_port = user['port']  # Get the port from the user dict to send messages
        self._user = user
        self._random_challenge = None
        # Implementation of finite state machines.
        self._current_state = 'init'
        self._state_machine = {
            'init': {'init': {'nxt_state': 'dh_1', 'action': self._init}},
            'dh_1': {'ok': {'nxt_state': 'hello', 'action': self._dh_1}},
            'hello': {'ok': {'nxt_state': 'resp', 'action': self._hello},
                      'error': {'nxt_state': 'error', 'action': self._error}},
            'resp': {'ok': {'nxt_state': 'chall', 'action': self._resp},
                     'error': {'nxt_state': 'error', 'action': self._error}},
            'chall': {'ok': {'nxt_state': 'ack_or_nack', 'action': self._chall},
                      'error': {'nxt_state': 'error', 'action': self._error}},
            'ack_or_nack': {'ok': {'nxt_state': 'text', 'action': self._ack_or_nack},
                            'error': {'nxt_state': 'error', 'action': self._error}},
            'text': {'ok': {'nxt_state': 'text', 'action': self.text},
                     'error': {'nxt_state': 'error', 'action': self._error}},
            'error': {'ok': {'nxt_state': 'chall', 'action': self._chall},
                      'error': {'nxt_state': 'error', 'action': self._error}}
        }

    def client_send_message(self, pdu_dict):
        """
        This function send PDU dictionary and get the server reply.
        :param pdu_dict: PDU dictionary
        :return: Decoded server message
        """
        self._client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._client.settimeout(5)
        self._client.connect((self._remote_ip, int(self._remote_port)))
        self._client.sendall(json.dumps(pdu_dict).encode('utf-8'))
        data = self._client.recv(1024)
        self._client.close()
        return data.decode('utf-8')

    def _init(self):
        """
        This function generate the DiffieHellman object. So that the DiffieHellman key pair can be get.
        e.g.: self._client_dh.public_key
        :return: This function executed successfully.
        """
        self._client_dh = DiffieHellman()
        print('Client Init Successful.')
        return "ok"

    def _error(self):
        """
        This function only be used when error exists. It will send an 'nack' to the server
        """
        pdu = generate_pdu('nack', None, self._key_dict)
        ret = self.client_send_message(pdu)
        print(ret)

    def _dh_1(self):
        """ STEP.1: DiffieHellman
        Do DiffieHellman Key Exchange Step1 (Client -> Server)
        :return: This function executed successfully.
        """
        # Constructing client PDUs and generating CRC, then send it
        dh_1_pdu = {'header': {'msg_type': 'dh_1', 'timestamp': time.time()},
                    'body': {'key': base64.b64encode(str(self._client_dh.public_key).encode('utf-8')).decode('utf-8'),
                             'user': self._user['username']}}
        dh_1_pdu['header']['crc'] = zlib.crc32(json.dumps(dh_1_pdu).encode('utf-8'))
        # Get the server-side PDU and get the server-side public key.
        dh_2_pdu = json.loads(self.client_send_message(dh_1_pdu))
        server_public_key = int(base64.b64decode(dh_2_pdu['body']['key']).decode('utf-8'))
        # Perform DiffieHellman key exchange
        self._client_dh.generate_shared_secret(server_public_key)
        user_password = self._user['password'].encode('utf-8')
        # Save the generated key to the class variable. self._key_dict will be used to generate PDU and decrypt the PDU
        hmac = HMAC.new(user_password, self._client_dh.shared_secret_bytes, digestmod=SHA256)
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
        return "ok"

    def _hello(self):
        """ STEP.3: Single CHAP
        Generate the 'hello' message and get the random bytes challenge value. save the random value to self._ran_chall
        :return: This function executed successfully.
        """
        pdu = generate_pdu('hello', None, self._key_dict)
        ret = self.client_send_message(pdu)
        pdu_dict = json.loads(ret)
        msg_type, plain_text = parse_pdu(pdu_dict, self._key_dict)
        self._ran_chall = plain_text
        return 'ok'

    def _resp(self):
        """ STEP.5: Single CHAP
        Response to the challenge message using HMAC. Send it back then get the ACK or NACK from server
        If ACK --> Everything is working fine. Single CHAP done.
        If NACK --> Something is wrong. Single CHAP failed.
        :return: This function executed successfully or not.
        """
        ct_HMAC = HMAC.new(self._chap_secret, self._ran_chall, digestmod=SHA256)
        pdu = generate_pdu('resp', ct_HMAC.digest(), self._key_dict)
        ret = self.client_send_message(pdu)
        pdu_dict = json.loads(ret)
        msg_type, plain_text = parse_pdu(pdu_dict, self._key_dict)
        if msg_type == 'ack':
            print('>>>Single CHAP OK')
            return "ok"
        if msg_type == 'nack':
            print('>>>Single CHAP ERROR')
            return "error"

    def _chall(self):
        """ STEP.7: Mutual CHAP
        If Single CHAP is OK, then Client is going to challenge the Server.
        Generate a random bytes challenge value then send it to the server
        :return: This function executed successfully.
        """
        self._random_challenge = urandom(32)
        pdu = generate_pdu('chall', self._random_challenge, self._key_dict)
        ret = self.client_send_message(pdu)
        pdu_dict = json.loads(ret)
        msg_type, self._hmac = parse_pdu(pdu_dict, self._key_dict)
        return 'ok'

    def _ack_or_nack(self):
        """ STEP.9: Mutual CHAP
        Receive the challenge response from the server and verify it.
        If verify correct --> send ACK back and Mutual CHAP OK
        If verify incorrect --> send NACK back and Mutual CHAP failed.
        :return: This function executed successfully or not.
        """
        ct_HMAC = HMAC.new(self._chap_secret, self._random_challenge, digestmod=SHA256)
        try:
            ct_HMAC.verify(self._hmac)
            pdu = generate_pdu('ack', None, self._key_dict)
        except Exception as e:
            pdu = generate_pdu('nack', None, self._key_dict)
        ret = self.client_send_message(pdu)
        pdu_dict = json.loads(ret)
        msg_type, plain_text = parse_pdu(pdu_dict, self._key_dict)
        if msg_type == 'ack':
            print('>>>Mutual CHAP OK')
            print('>>>You can send your message now. Type "close()" to exit.')
            return "text"
        if msg_type == 'nack':
            print('>>>Mutual CHAP ERROR')
            return "error"

    def text(self, text):
        """
        Send messages to the server. use 'close()' to shut the server and client down.
        :param text: plain text message from user input
        :return: This function executed successfully or not.
        """
        if text == 'close()':
            pdu = generate_pdu('close', text.encode('utf-8'), self._key_dict)
            self.client_send_message(pdu)
            print(">>>Bye")
            return 'init'
        else:
            pdu = generate_pdu('text', text.encode('utf-8'), self._key_dict)
            ret = self.client_send_message(pdu)
        pdu_dict = json.loads(ret)
        msg_type, plain_text = parse_pdu(pdu_dict, self._key_dict)
        if msg_type == 'ack':
            return "text"
        if msg_type == 'nack':
            return "error"

    def event_handler(self, event, *args):
        """
        Event manipulation functions for finite state machines.
        :param event: 'ok' or 'text' or 'error'
        :param args: When sending message, have to use the *args to get the parameter.
        :return: the function outcome
        """
        if self._current_state not in self._state_machine.keys():
            raise Exception(f'current state not in state list: {self._current_state}')
        nxt_state = self._state_machine[self._current_state][event]['nxt_state']
        action = self._state_machine[self._current_state][event]['action']
        if not args:
            ret = action()
        else:
            ret = action(args)
        self._current_state = nxt_state
        return ret


'''
# Testing functions. It CAN be used however you don't have to. I used this to test my code before I write the main.py
if __name__ == "__main__":
    directory_dict = decrypt_file_to_user_json('encrypted_directory.bin')
    user = select_user_from_table(directory_dict)
    client = Client(user)
    status = client.event_handler('init')
    while status:
        if status == 'ok':
            status = client.event_handler('ok')
        if status == 'text':
            message = input('message>')
            status = client.text(message)
        if status == 'error':
            print('error handler')
            status = client.event_handler('error')
'''
