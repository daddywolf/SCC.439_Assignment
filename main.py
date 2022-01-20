from utils.basic_functions import *

if __name__ == '__main__':
    print("Welcome to the Online Chat!")
    input_port()
    directory_dict = input_directory()
    show_directory_in_table(directory_dict)
    person = select_directory_individual(directory_dict)
    print(person)
    # connect = Connect()
    # connect.receive_message()
