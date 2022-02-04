import select
import socket
import sys

from connect.client import Client
from connect.server import Server
from mycryptolib.directory_protection import decrypt_file_to_user_json
from utils.basic_functions import select_user_from_table, print_yellow, print_green
from utils.config import WELCOME
from utils.secure_logging import log_to_file

"""
    This file is the main entrance of the whole program :-)
    You should run this file using 2 different terminals, and select 2 different users. Thus they can contact each other. 
    E.g.: On terminal 1: select 1 and 2; On terminal 2: select 2 and 1.
    Steps:
    1. Show Welcome message. If no public/private keys, then generate them. If no encrypted directory file, generate it.
    2. Ask the user to select themself.
    3. Ask the user to select a user they want to send messages to.
    4. If the user types something, then do DH key exchange and CHAP. When finished, the user can send messages.
    5. If the user types 'close()', close the server socket and ask the user to select a new user to send messages to.
    6. back to step 3.
"""
if __name__ == '__main__':
    print(WELCOME)
    # If no public/private key exists, should be generate first. And then convert a user list to a encrypted file.
    # generate_public_key_and_private_key_to_files()  # If no public key and private key, mush generate it first
    # encrypt_user_list_to_file()  # If no encrypted file, mush generate it first
    # Select who I am
    directory_dict = decrypt_file_to_user_json('encrypted_directory.bin')
    print_green("Please select YOURSELF:")
    me = select_user_from_table(directory_dict)
    print_yellow(f'Hi <{me["username"]}>! You are running a server on <{socket.gethostname()}:{me["port"]}>')
    # Select who you are
    while 1:
        print_green("Please select YOUR TARGET:         (CANNOT BE THE SAME AS YOUSELF!)")
        others = select_user_from_table(directory_dict)
        print_yellow(f"You want to send message to <{others['username']}> on <{others['ip']}:{others['port']}>.")
        # create a server and a client and initialize them
        client = Client(user=others)
        client_status = client.event_handler('init')
        server = Server(user=me)
        server_status = server.event_handler('init')
        # Do select.selct to let the server and client running in one thread. Waiting for keyboard interaction
        print("Enter your message and press enter...")
        inputs = [server.server, sys.stdin]
        while client_status != 'error' and server_status != 'error':
            readable, writable, exceptional = select.select(inputs, [], [], 25)
            # Server actions  --> see connect/server.py
            if server.server in readable:
                server_status = server.event_handler('ok')
            # Client actions  --> see connect/client.py
            elif sys.stdin in readable:
                if client_status == 'ok':
                    client_status = client.event_handler('ok')
                if client_status == 'text':
                    message = input()
                    log_to_file('message', (me, message))  # put user's name and its message to secure_log.log
                    client_status = client.text(message)
                    if message == 'close()':  # If user types 'close()', then close the local server socket and ask user to RE-SELECT a new user to send message
                        server.server.close()
                        break
                if client_status == 'error':
                    print('error handler')
                    client_status = client.event_handler('error')
