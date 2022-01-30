import hashlib
import os
import sys


class DiffieHellman:
    ''' Class for Diffie Hellman key exchange protocol '''

    def __init__(self) -> None:
        # RFC 3526 - More Modular Exponential (MODP) Diffie-Hellman groups for 
        # Internet Key Exchange (IKE) https://tools.ietf.org/html/rfc3526 
        # Using the default group 14
        self.__prime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
        self.__generator = 2

        # pub key is pub = gen ^ priv mod prime
        # https://docs.python.org/3/library/functions.html#pow
        self.__priv_key = int.from_bytes(os.urandom(32), byteorder=sys.byteorder, signed=False)
        self.__pub_key = pow(self.__generator, self.__priv_key, self.__prime)
        self.__shared_secret = 0

    @property
    def private_key(self):
        ''' Returns the private key '''
        return self.__priv_key

    @property
    def private_key_bytes(self):
        ''' Retursn the private key as a bytes object '''
        return self.__priv_key.to_bytes(32, sys.byteorder)

    @property
    def public_key(self):
        ''' Returns the public key '''
        return self.__pub_key

    @property
    def public_key_bytes(self):
        ''' Returned shte public key as a bytes object '''

        key_bl = self.__pub_key.bit_length()
        offset = key_bl % 8
        if offset != 0:
            offset = 8 - offset
        key_bl += offset
        key_bl = int(key_bl / 8)
        return self.__pub_key.to_bytes(key_bl, sys.byteorder)

    @property
    def shared_secret(self):
        ''' The generated shared secret'''
        return self.__shared_secret

    @property
    def shared_secret_bytes(self):
        ''' The generated shared secret as bytes object'''
        return self.__shared_secret.to_bytes(32, sys.byteorder)

    def rekey(self):
        ''' Re-generates the private key and then regens the public key '''
        self.__priv_key = int.from_bytes(os.urandom(32), byteorder=sys.byteorder, signed=False)
        self.__pub_key = pow(self.__generator, self.__priv_key, self.__prime)
        self.__shared_secret = 0

    def validate_public_key(self, pub_key=None):
        ''' Validates a public key as per NIST SP800-56'''
        # check if the other public key is valid based on NIST SP800-56
        # 2 <= g^b <= p-2 and Lagrange for safe primes (g^bq)=1, q=(p-1)/2
        if pub_key == None:
            pub_key = self.public_key
        if 2 <= pub_key and pub_key <= self.__prime - 2:
            if pow(pub_key, (self.__prime - 1) // 2, self.__prime) == 1:
                return True
        return False

    def generate_shared_secret(self, other_pub_key):
        ''' Generates a shared secret with someone elese '''
        if self.validate_public_key(other_pub_key):
            ss_key = pow(other_pub_key, self.__priv_key, self.__prime)
            ss_key_bl = ss_key.bit_length()
            offset = ss_key_bl % 8
            if offset != 0:
                offset = 8 - offset
            ss_key_bl += offset
            ss_key_bl = int(ss_key_bl / 8)
            ss_key_bytes = ss_key.to_bytes(int(ss_key_bl), sys.byteorder)

            self.__shared_secret = hashlib.sha256(ss_key_bytes).digest()
            self.__shared_secret = int.from_bytes(self.__shared_secret, sys.byteorder)
            return self.__shared_secret
        else:
            raise Exception("Bad public key from the other party")

    def __str__(self):
        ''' turn it in to a string'''
        out_str = "LU_DH: \n\tPriv: "
        out_str = out_str + f'{self.__priv_key:x}'
        out_str = out_str + "\n\tPub: "
        out_str = out_str + f'{self.__pub_key:x}'
        out_str = out_str + "\n\tShared: "
        out_str = out_str + f'{self.__shared_secret:x}'
        return out_str
