import base64
import json
import time


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

    def dh_key_exchange(self):
        if self._msg_type != 'DiffieHellman':
            raise Exception("Message Type not DiffieHellman!")
        basic_message_template = {'msg_type': 'DiffieHellman', 'body': self._message}
        return json.dumps(str(basic_message_template))

    def obj_to_json(self):
        basic_message_template = {
            "header": {
                # "crc": crc,
                "msg_type": self._msg_type,
                "timestamp": int(time.time())
            },
            "message": base64.b64encode(str(self._message).encode()).decode(),
            # "security": {
            #     "hmac": {
            #         "hmac_type": "SHA256",
            #         "hmac_val": h.hexdigest()
            #     },
            #     "enc_type": enc_type
            # }
        }
        return json.dumps(basic_message_template)

    def json_to_obj(self, json_data):
        dict = json.loads(json_data)
        self._msg_type = dict['header']['msg_type']
        self._message = base64.b64decode(dict['message']).decode()
        if dict['header'].get('crc'):
            self._crc = dict['header'].pop('crc')
