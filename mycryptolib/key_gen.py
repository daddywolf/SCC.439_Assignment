'''
Lancaster University 2022
A simple test application showing the creation of the key chain and the encryption and hashing of data

This programme can be used to verify that your key chain is correctly being created.
This code is drawn directly from the documentation of PyCryptodomeDome:
https://www.pyCryptodomedome.org/en/latest/src/hash/hash.html
https://www.pyCryptodomedome.org/en/latest/src/hash/hmac.html
https://www.pyCryptodomedome.org/en/latest/src/hash/sha256.html
https://www.pyCryptodomedome.org/en/latest/src/cipher/cipher.html
https://www.pyCryptodomedome.org/en/latest/src/cipher/classic.html
https://docs.python.org/3.9/tutorial/introduction.html#lists See List slicing

ALWAYS RTFM!
'''

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256, HMAC
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad

DHSK = get_random_bytes(32)  # DH returns a fixed length shared secret of 32 byte
user_secret = b'mysecret'  # User secret selected from the dictionary

hmac = HMAC.new(user_secret, DHSK, digestmod=SHA256)
enc_key = hmac.digest()  # Note we use the bytes object not the hex value for the key.

hash = SHA256.new()
hash.update(enc_key)
iv = hash.digest()[
     :16]  # The IV is a fixed length of 16 bytes. This notation fetchs bytes 0-15 (16 in total)[List slicing]
hash.update(iv)
hmac_key = hash.digest()
hash.update(hmac_key)
chap_secret = hash.digest()
print('Encryption Key: ', enc_key)
print('            iv: ', iv)
print('      HMAC Key: ', hmac_key)
print('   CHAP Secret: ', chap_secret)

# Proof of Encryption
data = b'hello world'
cipher = AES.new(enc_key, AES.MODE_CBC, iv)  # Create new cipher
ct_bytes = cipher.encrypt(pad(data, AES.block_size))  # Encrypt the data
ct_HMAC = HMAC.new(hmac_key, ct_bytes, digestmod=SHA256)  # Create new HMAC. Here we pass in the data directly
ct_hash = ct_HMAC.digest()  # Get the bytes digest
print('          data: ', data)
print('      ct_bytes: ', ct_bytes)
print('       ct_hash: ', ct_hash)

# Proof of decryption
decipher = AES.new(enc_key, AES.MODE_CBC, iv)  # Need a new decryption object
pt = unpad(decipher.decrypt(ct_bytes), AES.block_size)  # Get the plain text
print('       ct_text: ', pt)
verify_HMAC = HMAC.new(hmac_key, ct_bytes, digestmod=SHA256)  # New HMAC object
try:
    verify_HMAC.verify(ct_hash)  # Verify excepts if there is an error.
    print('       HMAC OK: True')
except Exception as e:
    print(e)
    print('       HMAC OK: False')
