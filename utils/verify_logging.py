from Cryptodome.Hash import HMAC, SHA256


class VerifyLogging:

    def __init__(self, filename=None):
        self._entry_count = None
        self._filename = filename
        self._file = None
        self._password = None
        self._error_count = None
        self._error_lines = None

    @property
    def error_count(self):
        return self._error_count

    @property
    def error_lines(self):
        return self._error_lines

    def check_order(self):
        self._file = open(self._filename, 'r')
        current_timestamp = 0
        while 1:
            res = self._file.readline().replace("\n", "").split("::")
            if res == ['']:
                break
            if int(current_timestamp) > int(res[0]):
                raise Exception('error')
            current_timestamp = res[0]

    def verify(self, file_name, password):
        self._file = open(file_name, 'r')
        error_dict = {}
        count = 0
        while 1:
            count += 1
            res = self._file.readline().replace("\n", "").split("::")
            if res == ['']:
                break
            hmac = HMAC.new(password.encode(), digestmod=SHA256)
            hmac.update(f"{res[0]}::{res[1]}::{res[2]}::{password}".encode())
            try:
                hmac.hexverify(res[3])
            except ValueError:
                error_dict[count] = res
        self._error_count = len(error_dict)
        self._error_lines = list(error_dict.values())
