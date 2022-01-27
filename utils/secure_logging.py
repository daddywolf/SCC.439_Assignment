import time

from Cryptodome.Hash import HMAC, SHA256

from utils.config import LOG_FILE


class SecureLogging:

    def __init__(self):
        self._entry_count = None
        self._filename = None
        self._file = None
        self._password = None

    @property
    def entry_count(self):
        return

    @entry_count.setter
    def entry_count(self, value):
        pass

    @property
    def filename(self):
        return self._filename

    @filename.setter
    def filename(self, value):
        self._filename = value

    def open(self, file_name, password):
        self._file = open(file_name, 'a')
        self._password = password

    def close(self):
        if self._file:
            self._file.close()
        else:
            print("no file opened")

    def log(self, level, message):
        timestamp = int(time.time())
        hmac = HMAC.new(self._password.encode(), digestmod=SHA256)
        message_format = f"{timestamp}::{level}::{message}::{self._password}"
        hmac.update(message_format.encode())
        log_format = f"{timestamp}::{level}::{message}::{hmac.hexdigest()}\n"
        self._file.writelines(log_format)
        return log_format


def log_to_file(level, message):
    sl = SecureLogging()
    sl.open(LOG_FILE, '666')
    sl.log(level, message)
