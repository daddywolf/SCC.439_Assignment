import base64

from utils.basic_functions import *

if __name__ == '__main__':
    print("Welcome to the Online Chat!")
    input_port()
    directory_dict = input_directory()
    person = show_directory_in_table(directory_dict)
    print(person)
    # connect = Connect()
    # connect.receive_message()
    print(base64.encodebytes(b'1'))
