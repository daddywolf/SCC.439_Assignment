import select
import sys

from connect.new_client import Client
from connect.new_server import Server
from utils.basic_functions import input_directory, select_user_from_table, input_port
from utils.config import WELCOME

if __name__ == '__main__':
    print(WELCOME)
    # parser = argparse.ArgumentParser()
    # parser.add_argument('--port', action='store', dest='port', type=int, required=True)
    # given_args = parser.parse_args()
    # port = given_args.port
    username = input("Input username: ")
    local_server_port = input_port()
    print(f'Hi <{username}>! You are running a server on <0.0.0.0:{local_server_port}>')
    directory_dict = input_directory('directory.json')
    user = select_user_from_table(directory_dict)
    print(f"You want to send message to <{user['username']}> on <{user['ip']}:{user['port']}>.")
    client = Client(user['ip'], user['port'], user)
    client_status = client.event_handler('init')
    server = Server(local_server_port)
    server_status = server.event_handler('init')
    print("Press any key to send message...")
    inputs = [server.server, sys.stdin]
    while 1:
        readable, writable, exceptional = select.select(inputs, [], [])
        if server.server in readable:
            server.event_handler('ok')
        if sys.stdin in readable:
            try:
                status = client.event_handler('ok')
            except:
                message = input()
                if message != "":
                    status = client.text(message)
