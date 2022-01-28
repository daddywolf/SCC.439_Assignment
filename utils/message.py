import base64
import json
import time
import zlib

from Cryptodome.Hash import HMAC, SHA256


class Message:
    def __init__(self, msg_type=None, message=None, message_json=None):
        self._msg_type = msg_type
        self._message = message
        if message_json:
            self.json_to_obj(message_json)

    @property
    def msg_type(self):
        return self._msg_type

    @property
    def message(self):
        return self._message

    def obj_to_json(self):
        message_template = {
            "header": {
                "msg_type": self._msg_type,
                "timestamp": int(time.time())
            },
            "message": base64.b64encode(str(self._message).encode()).decode(),  # 1 Base64
        }
        # 2 Encryption
        # TODO
        # 3 HMAC Calculate
        h = HMAC.new(b'hmac_key', digestmod=SHA256)
        h.update(json.dumps(message_template).encode())
        if not self._msg_type == 'DiffieHellman':  # Only DH process do not require security methods
            message_template['security'] = {'hmac': {'hmac_type': 'SHA256', 'hmac_val': h.hexdigest()},
                                            'enc_type': 'AES256 CBC'}
        # 4 CRC Calculate
        message_template['header']['crc'] = zlib.crc32(json.dumps(message_template).encode())
        return json.dumps(message_template)

    def json_to_obj(self, json_data):
        dict = json.loads(json_data)
        # 4 CRC Verify
        if dict['header'].get('crc'):
            self._crc = dict['header'].pop('crc')
            new_crc = zlib.crc32(json.dumps(dict).encode())
            assert self._crc == new_crc, "CRC CHECK FAILED"
        # 3 HMAC Verify
        if dict.get('security'):
            security = dict.pop('security')
            h = HMAC.new(b'hmac_key', digestmod=SHA256)
            h.update(json.dumps(dict).encode())
            try:
                h.hexverify(security['hmac']['hmac_val'])
            except ValueError:
                print("The message or the key is wrong")
        # 2 Decryption
        # TODO
        self._msg_type = dict['header']['msg_type']
        self._message = base64.b64decode(dict['message']).decode()  # 1 Base64
