import random

from connection.client import Client
from connection.server import Server
from utils.basic_functions import *
# python main.py --file directory.json --port 8889
from utils.message import Message
from utils.welcome import welcome

if __name__ == '__main__':
    print(welcome)
    # parser = argparse.ArgumentParser()
    # parser.add_argument('--file', action='store', dest='file', required=True)
    # parser.add_argument('--port', action='store', dest='port', type=int, required=True)
    # given_args = parser.parse_args()
    # file = given_args.file
    # port = given_args.port
    file = 'directory.json'
    port = int(input('Port:'))
    directory_dict = input_directory(file)
    send_or_receive = input("What do you want to do? (send/receive)")
    if send_or_receive == 'send':
        client = Client(port=port)
        client.send_message(Message('DiffieHellman', random.randint(1, 10)).obj_to_json())
    elif send_or_receive == 'receive':
        print('Server Listening...')
        server = Server(port=port)
        server.receive_message('111')
    else:
        raise Exception("input Error")
