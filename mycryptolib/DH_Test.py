from Cryptodome.Hash import SHA256, HMAC

from mycryptolib.lancs_DH import DiffieHellman

if __name__ == "__main__":
    client = DiffieHellman()
    server = DiffieHellman()
    print(f"client public key: {client.public_key}")
    print(f"server public key: {server.public_key}")
    client.generate_shared_secret(server.public_key)
    server.generate_shared_secret(client.public_key)
    print(f"client shared secret {client.shared_secret_bytes}")
    print(f"server shared secret {server.shared_secret_bytes}")

    user_password = '123456'
    hmac = HMAC.new(user_password.encode(), client.shared_secret_bytes, digestmod=SHA256)
    enc_key = hmac.digest()
    print(enc_key)

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