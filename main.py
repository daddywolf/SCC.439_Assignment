import select
import socket
import sys

from connect.client import Client
from connect.server import Server
from mycryptolib.directory_protection import decrypt_file_to_user_json, generate_public_key_and_private_key_to_files, \
    encrypt_user_list_to_file
from utils.basic_functions import select_user_from_table, print_yellow, print_green
from utils.config import WELCOME
from utils.secure_logging import log_to_file

if __name__ == '__main__':
    print(WELCOME)
    generate_public_key_and_private_key_to_files()  # If no public key and private key, mush generate it first
    encrypt_user_list_to_file()  # If no encrypted file, mush generate it first
    directory_dict = decrypt_file_to_user_json('encrypted_directory.bin')
    print_green("Please select YOURSELF:")
    me = select_user_from_table(directory_dict)
    print_yellow(f'Hi <{me["username"]}>! You are running a server on <{socket.gethostname()}:{me["port"]}>')
    print_green("Please select YOUR TARGET:         (CANNOT BE THE SAME AS YOUSELF!)")
    others = select_user_from_table(directory_dict)
    print_yellow(f"You want to send message to <{others['username']}> on <{others['ip']}:{others['port']}>.")
    client = Client(others['ip'], others['port'], others)
    client_status = client.event_handler('init')
    server = Server(me["port"])
    server_status = server.event_handler('init')
    print("Press any key to send message...")
    inputs = [server.server, sys.stdin]
    while client_status != 'error' and server_status != 'error':
        readable, writable, exceptional = select.select(inputs, [], [])
        if server.server in readable:
            server_status = server.event_handler('ok')
        if sys.stdin in readable:
            if client_status == 'ok':
                client_status = client.event_handler('ok')
            if client_status == 'text':
                message = input()
                log_to_file('message', (me, message))
                client_status = client.text(message)
            if client_status == 'error':
                print('error handler')
                client_status = client.event_handler('error')
