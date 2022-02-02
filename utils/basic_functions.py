import base64
import json
import time
import zlib

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256, HMAC
from Cryptodome.Util.Padding import pad, unpad


def input_port():
    port = input("Please enter a port to incoming connections: ")
    if not port:
        port = 8888
    port = int(port)
    if port < 1 or port > 65535:
        print("Port input error. Please try again.")
        input_port()
    return port


def input_directory(filename):
    directory_file = f"files/{filename}"
    with open(directory_file) as file:
        directory_list = json.load(file)
    return directory_list


def select_user_from_table(dict_list):
    if not dict_list:
        print("No individuals available.")
        return
    print("id\t\tip\t\t\tport\t\tusername")
    print("---------------------------------------------------------------------")
    user_id = 0
    for i in dict_list:
        user_id += 1
        print(f"{user_id}\t\t{i['ip']}\t\t{i['port']}\t\t{i['username']}")
    target = int(input("Please select the target (id):"))
    if target < 1 or target > len(dict_list):
        print("Target input error. Please try again.")
        return select_user_from_table(dict_list)
    else:
        return dict_list[target - 1]


def generate_pdu(msg_type, data, key_dict):
    body = None
    if data:
        cipher = AES.new(key_dict['enc_key'], AES.MODE_CBC, key_dict['iv'])
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        body = base64.b64encode(ct_bytes).decode('utf-8')
    pdu = {'header': {'msg_type': msg_type, 'timestamp': time.time(), 'crc': 0x00}, 'body': body,
           'security': {'hmac': {'type': 'SHA256', 'val': 0x00}, 'enc_type': 'AES256-CBC'}}
    ct_HMAC = HMAC.new(key_dict['hmac_key'], json.dumps(pdu).encode('utf-8'), digestmod=SHA256)
    pdu['security']['hmac']['val'] = base64.b64encode(ct_HMAC.digest()).decode('utf-8')
    pdu['header']['crc'] = zlib.crc32(json.dumps(pdu).encode('utf-8'))
    print_green(pdu)
    return pdu


def decrypt_pdu(pdu_dict, key_dict):
    crc_other = pdu_dict['header'].pop('crc')
    pdu_dict['header']['crc'] = 0x00
    crc_my = zlib.crc32(json.dumps(pdu_dict).encode('utf-8'))
    if not crc_other == crc_my:
        raise Exception("CRC ERROR")
    hmac_other = pdu_dict['security']['hmac'].pop('val')
    pdu_dict['security']['hmac']['val'] = 0x00
    hmac_my = HMAC.new(key_dict['hmac_key'], json.dumps(pdu_dict).encode('utf-8'), digestmod=SHA256)
    try:
        hmac_my.verify(base64.b64decode(hmac_other))
    except Exception as e:
        print('       HMAC OK: False')
    if pdu_dict['body']:
        ct_bytes = base64.b64decode(pdu_dict['body'])
        decipher = AES.new(key_dict['enc_key'], AES.MODE_CBC, key_dict['iv'])
        pt = unpad(decipher.decrypt(ct_bytes), AES.block_size)
        return pdu_dict['header']['msg_type'], pt
    else:
        return pdu_dict['header']['msg_type'], None


def print_green(text):
    print(f'\033[92m{text}\033[0m')


def print_yello(text):
    print(f'\033[93m{text}\033[0m')


def print_red(text):
    print(f'\033[91m{text}\033[0m')
