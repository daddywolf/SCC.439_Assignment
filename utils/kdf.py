# Uses PyCryptoDome for the cryptographic functions
# https://pycryptodome.readthedocs.io/en/latest/index.html
# follows https://www.ietf.org/rfc/rfc2104.txt
#    We define two fixed and different strings ipad and opad as follows
#   (the 'i' and 'o' are mnemonics for inner and outer):
#
#                  ipad = the byte 0x36 repeated B times
#                  opad = the byte 0x5C repeated B times.
#
#   To compute HMAC over the data `text' we perform
#
#                    H(K XOR opad, H(K XOR ipad, text))
#
#   Namely,
#
#    (1) append zeros to the end of K to create a B byte string
#        (e.g., if K is of length 20 bytes and B=64, then K will be
#         appended with 44 zero bytes 0x00)
#    (2) XOR (bitwise exclusive-OR) the B byte string computed in step
#        (1) with ipad
#    (3) append the stream of data 'text' to the B byte string resulting
#        from step (2)
#    (4) apply H to the stream generated in step (3)
#    (5) XOR (bitwise exclusive-OR) the B byte string computed in
#        step (1) with opad
#    (6) append the H result from step (4) to the B byte string
#        resulting from step (5)
#    (7) apply H to the stream generated in step (6) and output
#        the result
from Cryptodome.Hash import SHA3_256


class KDF:
    def __init__(self):
        self._k = 0
        self._k_fixed = 0
        self._k_ipad = 0
        self._k_opad = 0
        self._inner_h_obj = None
        self._outer_h_obj = None
        pass

    # set_key(key)
    #
    # key = is the salt that is used in the KDF HMAC
    def set_key(self, key):
        if type(key) is not bytes:
            raise Exception("key is not bytes")
        self._k = key
        key_array = bytearray(key)

        # if the key is not of the right length we pad with zeros if too short
        # or hash if too short. The length needs to be the length of the output 
        # hash. in this case 32 bytes
        l = len(key_array)  # get the length of the key in bytes
        if l > 32:
            h_obj = SHA3_256.new(key)
            key_array = bytearray(h_obj.digest())
        elif l < 32:
            # See list comprehensions 
            # https://docs.python.org/3/tutorial/datastructures.html?highlight=lists#list-comprehensions
            key_array.extend([0x00 for _ in range(32 - l)])
        self._k_fixed = key_array
        # https://docs.python.org/3/library/functions.html#zip 
        # https://docs.python.org/3/tutorial/datastructures.html?highlight=lists#list-comprehensions
        # zip combines the elements from two lists and returns them as a tuple 
        # one of the lists going into zip is list comprehension which creates the fixed length ipad or opad with the correct hex values
        # the outer list comprehension then iterates each value in the returned tuple from the zip and XORs it
        # this creates a new list of the combination
        self._k_ipad = bytearray([_a ^ _b for _a, _b in zip(key_array, [0x36 for _ in range(32)])])
        self._k_opad = bytearray([_a ^ _b for _a, _b in zip(key_array, [0x5C for _ in range(32)])])
        # make sure any previous hash info is cleared
        self._inner_h_obj = None
        self._outer_h_obj = None

    # Update(data)
    # data = the information to be hashed.
    # returns the binary digest (256 bits) of information as a bytes object
    def update(self, data):
        if type(data) is not bytes:
            raise Exception("data is not bytes")

        self._inner_h_obj = SHA3_256.new(self._k_ipad + bytearray(data))
        self._outer_h_obj = SHA3_256.new(self._k_opad + self._inner_h_obj.digest())
        self._digest = self._outer_h_obj.digest()
        return self._outer_h_obj.digest()

    # digest()
    # fetches the current hmac digest as a binary bytes object
    def digest(self):
        return self._outer_h_obj.digest()

    # hexdigest()
    # returns a string version of the digest in hex
    def hexdigest(self):
        return self._outer_h_obj.hexdigest()


if __name__ == "__main__":
    kdf = KDF()
    kdf.set_key(b'bobbo')
    # kdf.set_key(bytes([0x00 for _ in range(32)]))

    kdf.update(b'test data')
    print(f'key in hex:        {kdf._k.hex()}')
    print(f'key fixed in hex:  {kdf._k_fixed.hex()}')
    print(f'key ipad in hex:   {kdf._k_ipad.hex()}')
    print(f'key opad in hex:   {kdf._k_opad.hex()}')
    print(f'Inner hash in hex: {kdf._inner_h_obj.hexdigest()}')
    print(f'Outer hash in hex: {kdf.hexdigest()}')
