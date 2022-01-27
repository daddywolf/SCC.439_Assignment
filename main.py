import argparse

from connection.server import Server
from utils.basic_functions import *

# python main.py --file directory.json --port 8889


if __name__ == '__main__':
    print("Welcome to the Online Chat!")
    parser = argparse.ArgumentParser()
    parser.add_argument('--file', action='store', dest='file', required=True)
    parser.add_argument('--port', action='store', dest='port', type=int, required=True)
    given_args = parser.parse_args()
    file = given_args.file
    port = given_args.port
    if port:
        server = Server(port=port)
    directory_dict = input_directory(file)
    person = show_directory_in_table(directory_dict)
    print(person)
