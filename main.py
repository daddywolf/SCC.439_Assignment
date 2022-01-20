from utils.basic_functions import *
from utils.logger import log

if __name__ == '__main__':
    print("Welcome to the Online Chat!")
    input_port()
    directory_dict = input_directory()
    person = show_directory_in_table(directory_dict)
    print(person)
    # connect = Connect()
    # connect.receive_message()
