from socket import *
import threading

def get_line(conn):
    msg = b''
    while True:
        ch = conn.recv(1)
        msg += ch
        if ch == b'\n' or len(ch) == 0:
            break
    return msg.decode().strip()


def get():
    pass

def insert():
    pass

def remove():
    pass

def contains():
    pass

def locate():
    pass

def connect():
    pass

def disconnect():
    pass

def update_prev():
    pass

# Initial setup
port = 12345
socket = socket(AF_INET, SOCK_STREAM)
socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
socket.bind( ('', port) )
socket.listen(16)

print("DHT Running...")
print("Listening on port:", port)

try:
    # Spawn a thread that listens
    # Main thread handles user input
except KeyboardInterrupt:
    print("\n DHT Shutting Down...")
    socket.close()
