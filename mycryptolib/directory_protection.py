import json

from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes

from utils.config import PATH


def encrypt_user_list_to_file():
    """
    If there is no encrypted directory file, use this function to generate a encrypted directory file
    The 'data' SHOULDN'T write inside the python file like this. BUT for the convenient, I have to do this. :-(
    (I included this as a vulnerability to the vulnerability text documentation.)
    :return: None
    """
    data = [
        {
            "username": "jiangzhipeng",
            "password": "111111",
            "port": "7777",
            "ip": "127.0.0.1"
        },
        {
            "username": "jiangkaiwen",
            "password": "222222",
            "port": "7778",
            "ip": "127.0.0.1"
        },
        {
            "username": "weichengyang",
            "password": "333333",
            "port": "7779",
            "ip": "127.0.0.1"
        },
        {
            "username": "wangxinzhong",
            "password": "444444",
            "port": "7780",
            "ip": "127.0.0.1"
        }
    ]
    file_out = open(PATH + "encrypted_directory.bin", "wb")
    recipient_key = RSA.import_key(open(PATH + "public_key.pem").read())
    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(json.dumps(data).encode())
    [file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
    file_out.close()


def decrypt_file_to_user_json(filename):
    """
    Get the encrypted directory file and decrypt it to a normal user list.
    :param filename: encrypted directory file name
    :return: decrypted user list
    """
    file_in = open(PATH + filename, "rb")
    private_key = RSA.import_key(open(PATH + "private_key.pem").read())
    enc_session_key, nonce, tag, ciphertext = [file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)]
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return json.loads(data.decode("utf-8"))


def generate_public_key_and_private_key_to_files():
    """
    If there is no public key and private key files, generate them.
    THE PRIVATE KEY SHOULD BE STORED CAREFULLY! (I included this as a vulnerability to the vulnerability text documentation.)
    :return: Two PEM key files to 'files' folder
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open(PATH + "private_key.pem", "wb")
    file_out.write(private_key)
    file_out.close()
    print('Generate Private Key Success')

    public_key = key.publickey().export_key()
    file_out = open(PATH + "public_key.pem", "wb")
    file_out.write(public_key)
    file_out.close()
    print('Generate Public Key Success')
