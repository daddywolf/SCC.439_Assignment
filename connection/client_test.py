import socket
import time

from connection.client_state_machine import ClientStateMachine

HOST = '0.0.0.0'  # The remote host
PORT = 8888  # The same port as used by the server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
csm = ClientStateMachine()
csm.event_handler('init')
while 1:
    s.sendall(csm.event_handler('ok').encode())
    data = s.recv(1024)
    print('Echo', repr(data.decode()))
    time.sleep(1)
