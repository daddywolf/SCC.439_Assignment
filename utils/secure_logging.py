import time

from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.Util.Padding import pad, unpad

from utils.config import LOG_PASSWORD, LOG_KEY, PATH, LOG_FILE


class SecureLogging:
    def __init__(self, filename):
        self._file = open(PATH + filename, 'a')
        self._hmac = HMAC.new(LOG_PASSWORD, LOG_KEY, digestmod=SHA256)
        self._enc_key = self._hmac.digest()
        self._hash = SHA256.new()
        self._hash.update(self._enc_key)
        self._iv = self._hash.digest()[:16]

    def _log_encryption(self, data):
        data = data.encode()
        cipher = AES.new(self._enc_key, AES.MODE_CBC, self._iv)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        return ct_bytes

    def _log_decryption(self, data):
        data = data.encode()
        decipher = AES.new(self._enc_key, AES.MODE_CBC, self._iv)
        pt = unpad(decipher.decrypt(data), AES.block_size)
        return pt.decode()

    def log(self, level, message):
        timestamp = int(time.time())
        message_format = f"{timestamp}::{level}::{message[0]['username']}::{self._log_encryption(message[1])}"
        self._hmac.update(message_format.encode())
        log_format = message_format + f"::{self._hmac.hexdigest()}\n"
        self._file.writelines(log_format)
        return log_format


def log_to_file(level, message):
    sl = SecureLogging(LOG_FILE)
    sl.log(level, message)
