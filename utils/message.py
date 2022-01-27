import base64
import json
import time

from Cryptodome.Hash import HMAC, SHA256


class Message:
    def __init__(self, msg_type=None, message=None):
        self._msg_type = msg_type
        self._message = message

    def generate_message(self):
        h = HMAC.new(b'AkakoXo', digestmod=SHA256)
        h.update(b'data')
        enc_type = 'AES256'
        basic_message_template = {
            "header": {
                # "crc": crc,
                "msg_type": self._msg_type,
                "timestamp": int(time.time())
            },
            "message": base64.b64encode(self._message.encode()).decode(),
            "security": {
                # "hmac": {
                #     "hmac_type": "SHA256",
                #     "hmac_val": h.hexdigest()
                # },
                "enc_type": enc_type
            }
        }
        return json.dumps(str(basic_message_template))


if __name__ == "__main__":
    m = Message('hello', '')
    print(m.generate_message())
