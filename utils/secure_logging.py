import time

from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, SHA256
from Cryptodome.Util.Padding import pad, unpad

from utils.config import LOG_PASSWORD, LOG_KEY, LOG_FILE, PATH


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
        data = bytes(data)
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

    def read_logs(self, filename):
        self._file = open(PATH+filename, 'r')
        count = 0
        while 1:
            count += 1
            res = self._file.readline().replace("\n", "")
            print(res)
            print(res.split("::"))
            if res == ['']:
                break
            print(res)
            hmac = HMAC.new(LOG_PASSWORD, LOG_KEY, digestmod=SHA256)
            hmac.update(f"{res[0]}::{res[1]}::{res[2]}::{res[3]}".encode())
            try:
                hmac.hexverify(res[4])
            except ValueError:
                print("HMAC ERROR")
            plain_text_log = f"{res[0]}::{res[1]}::{res[2]}::{self._log_decryption(res[3])}"
            print(plain_text_log)


def log_to_file(level, message):
    sl = SecureLogging(LOG_FILE)
    sl.log(level, message)


if __name__ == "__main__":
    sl = SecureLogging(LOG_FILE)
    sl.read_logs(LOG_FILE)
