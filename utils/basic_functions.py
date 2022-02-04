import base64
import json
import time
import zlib

from Cryptodome.Cipher import AES
from Cryptodome.Hash import SHA256, HMAC
from Cryptodome.Util.Padding import pad, unpad


def select_user_from_table(dict_list):
    """
    Show a "table" to user. Let the user select a user id from the table.
    :param dict_list: decrypted user directory list
    :return: display a simple table to the user, and return the selected user dict.
    """
    if not dict_list:
        print("No individuals available.")
        return
    print("id\t\tip\t\t\tport\t\tusername")
    print("---------------------------------------------------------------------")
    user_id = 0
    for i in dict_list:
        user_id += 1
        print(f"{user_id}\t\t{i['ip']}\t\t{i['port']}\t\t{i['username']}")
    target = int(input("Please select the user (id):"))
    if target < 1 or target > len(dict_list):
        print("Target input error. Please try again.")
        return select_user_from_table(dict_list)
    else:
        return dict_list[target - 1]


def generate_pdu(msg_type, data, key_dict):
    """
    This function is the inverse function of parse_pdu.
    All PDUs except DiffieHellman key exchange are generated using this function.
    :param msg_type: PDU message type in the header
    :param data: plain text message data
    :param key_dict: Because I extracted this function from the client/server class to reduce code duplication, I need to pass in a dictionary of keys.
    :return: Encrypted and HMACed and CRCed PDU dict
    """
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


def parse_pdu(pdu_dict, key_dict):
    """
    This function is the inverse function of generate_pdu.
    All PDUs except DiffieHellman key exchange are parsed using this function.
    :param pdu_dict: Received PDU dict
    :param key_dict: Because I extracted this function from the client/server class to reduce code duplication, I need to pass in a dictionary of keys.
    :return: msg_type: PDU message type in the header, data: plain text message data
    """
    crc_other = pdu_dict['header'].pop('crc')
    pdu_dict['header']['crc'] = 0x00
    crc_my = zlib.crc32(json.dumps(pdu_dict).encode('utf-8'))
    assert crc_my == crc_other
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
        plain_text = unpad(decipher.decrypt(ct_bytes), AES.block_size)
        return pdu_dict['header']['msg_type'], plain_text
    else:
        return pdu_dict['header']['msg_type'], None


def print_green(text):
    # Print the green characters. This function is generally used to display PDUs.
    print(f'\033[92m{text}\033[0m')


def print_yellow(text):
    # Print the yellow characters. This function is generally used to display your own selection.
    print(f'\033[93m{text}\033[0m')


def print_red(text):
    # Print the red characters. This function is generally used to display information about the other side.
    print(f'\033[91m{text}\033[0m')
