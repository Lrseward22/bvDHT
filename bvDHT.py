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
    """
    [Self->Peer] GET
    [Self->Peer] HashedKey
    [Peer->Self] Acknowledgement of ownership of HashedKey Space Bail out if answer is ‘0’\n
    [Peer->Self] integer len(ValueData)
    [Peer->Self] byteArray of ValueData
    """
    pass

def insert():
    """
    [Self->Peer] INSERT
    [Self->Peer] HashedKey
    [Peer->Self] Acknowledgement of ownership of HashedKey Space, Bail out if answer is ‘0’\n
    [Self->Peer] integer len(ValueData)
    [Self->Peer] byteArray of ValueData
    [Peer->Self] Acknowledgement of successful INSERT
    """
    pass

def remove():
    """
    [Self->Peer] REMOVE
    [Self->Peer] HashedKey
    [Peer->Self] Acknowledgement of ownership of HashedKey Space Bail out if answer is ‘0’\n
    [Peer->Self] Acknowledgement of successful REMOVE
    Also acknowledge ‘1’ if key didn’t exist. Remove didn’t fail.
    """
    pass

def contains():
    """
    [Self->Peer] CONTAINS
    [Self->Peer] HashedKey
    [Peer->Self] Acknowledgement of ownership of HashedKey Space Bail out if answer is ‘0’\n
    [Peer->Self] Acknowledgement of having entry
    """
    pass

def locate():
    """
    [Self->Peer] LOCATE
    [Self->Peer] HashedKey
    [Peer->Self] PeerAddress
    """
    pass

def connect():
    """
    [Self->Peer] CONNECT
    [Self->Peer] HashedKey (of Self’s PeerAddress)
    [Peer->Self] Acknowledgement if 1, continue on – if 0, bail out of protocol
    Transfer all entries
    [Peer->Self] integer numEntries
    For loop – numEntries times do the following:
    [Peer->Self] HashKey of entry
    [Peer->Self] integer len(ValueData)
    [Peer->Self] byteArray of ValueData
    [Peer->Self] PeerAddress of it’s Next peer
    Complete Update Prev on Next Node sub-protocol
    Self->Peer] PeerAddress of Self
    *** Ownership Officially Transferred by completing this ***
    """
    pass

def disconnect():
    """
    [Self->Prev] DISCONNECT
    [Self->Prev] HashedKey (of Self’s Next PeerAddress)
    Transfer all entries
    [Self->Prev] integer numEntries
    For loop – numEntries times do the following:
    [Self->Prev] HashKey of entry
    [Self->Prev] integer len(ValueData)
    [Self->Prev] byteArray of ValueData
    Prev performs UpdatePrev on Next
    [Prev->Self] Acknowledgement
    *** Ownership Officially Transferred by completing this ***
    """
    pass

def update_prev():
    """
    [Self->Next] UPDATE_PREV
    [Self->Next] PeerAddress of self
    [Next->Self] Acknowledgement
    """

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
    pass
except KeyboardInterrupt:
    print("\n DHT Shutting Down...")
    socket.close()
