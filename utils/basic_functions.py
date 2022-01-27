import json


def input_port():
    port = input("Please enter a port to incoming connections: ")
    if not port:
        port = 8888
    port = int(port)
    if port < 1 or port > 65535:
        print("Port input error. Please try again.")
        input_port()
    return port


def input_directory(filename):
    directory_file = f"files/{filename}"
    with open(directory_file) as file:
        directory_list = json.load(file)
        print("Directory File Load Successfully!")
    return directory_list


def show_directory_in_table(dict_list):
    if not dict_list:
        print("No individuals available.")
        return
    print("id\t\tip\t\t\tport\t\tusername\t\tpassword")
    user_id = 0
    for i in dict_list:
        user_id += 1
        print(f"{user_id}\t\t{i['ip']}\t\t{i['port']}\t\t{i['username']}\t\t{i['password']}")
    target = int(input("Please select the target (id):"))
    if target < 1 or target > len(dict_list):
        print("Target input error. Please try again.")
        return show_directory_in_table(dict_list)
    else:
        return dict_list[target - 1]
