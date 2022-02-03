import select
import socket
import sys

from connect.new_client import Client
from connect.new_server import Server
from utils.basic_functions import input_directory, select_user_from_table, print_yellow
from utils.config import WELCOME

if __name__ == '__main__':
    print(WELCOME)
    # parser = argparse.ArgumentParser()
    # parser.add_argument('--port', action='store', dest='port', type=int, required=True)
    # given_args = parser.parse_args()
    # port = given_args.port
    directory_dict = input_directory('directory.json')
    print("Please select YOURSELF:")
    me = select_user_from_table(directory_dict)
    print_yellow(f'Hi <{me["username"]}>! You are running a server on <{socket.gethostname()}:{me["port"]}>')
    print("Please select YOUR TARGET:         (CANNOT BE THE SAME AS YOUSELF!)")
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
                message = input('message>')
                client_status = client.text(message)
            if client_status == 'error':
                print('error handler')
                client_status = client.event_handler('error')