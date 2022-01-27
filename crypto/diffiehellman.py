# Uses PyCryptoDome for the cryptographic functions
# https://pycryptodome.readthedocs.io/en/latest/index.html
from Cryptodome.Random.random import getrandbits


class DiffieHellman:
    # __init__
    # initialise a Diffie Hellman basic approach wth a prime and a base
    def __init__(self, prime, base):
        self._prime = prime
        self._base = base
        self._secret = {"priv_key": 0, "pub_key": 0, "thier_pub_key": 0, "shared_secret": 0}

    # generate_key_pair
    # priv_key=0, if 0 then a random key is generated. otherwise the defined key is set
    # This function overwrites any previous public private key pair
    # based on the prime, base and the priv_key a public key will be generate
    # returns the generated public key
    def generate_key_pair(self, priv_key=0):
        self._secret = {"priv_key": 0, "pub_key": 0, "thier_pub_key": 0, "shared_secret": 0}
        if priv_key == 0:
            priv_key = getrandbits(16)
        self._secret['priv_key'] = priv_key
        self._secret['pub_key'] = (self._base ** priv_key) % self._prime
        return self._secret['pub_key']

    # generate_shared_secret
    # their_pub_key is the public key shared by the other party
    # overwrites the previous public key and the shared secret
    # returns the calculated shared secret
    def generate_shared_secret(self, their_pub_key):
        self._secret['their_pub_key'] = their_pub_key
        secret = (their_pub_key ** self._secret['priv_key']) % self._prime
        self._secret['shared_secret'] = secret
        return self._secret['shared_secret']

    @property
    def public_key(self):
        return self._secret['pub_key']

    @property
    def private_key(self):
        return self._secret['priv_key']

    @property
    def shared_secret(self):
        return self._secret['shared_secret']
