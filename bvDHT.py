from socket import *
from sys import argv
from typing import Tuple
import threading
import hashlib


#################### Util Functions #################
def get_line(conn) -> str:
    msg = b''
    while True:
        ch = conn.recv(1)
        msg += ch
        if ch == b'\n' or len(ch) == 0:
            break
    return msg.decode().strip()

def recvall(conn, msgLength: int) -> bytes:
    msg = b''
    while len(msg) < msgLength:
        retVal = conn.recv(msgLength - len(msg))
        msg += retVal
        if len(retVal) == 0:
            break    
    return msg

# Hashed key for self connection
def getHashIndex(addr: Tuple[str, int]) -> int:
    b_addrStr = ("%s:%d" % addr).encode()
    return int.from_bytes(hashlib.sha1(b_addrStr).digest(), byteorder="big")

# Hashed key for any string
def getHashKey(data: str):
    return int.from_bytes(hashlib.sha1(data.encode()).digest(), byteorder="big")

def update_prev_finger(peerAddr: Tuple[str, int], hashedKey: int) -> bool:
    print("Updating prev peer.")
    peerInformation["prev"] = peerAddr
    return True

# Returns IP address of self
def getLocalIPAddress() -> str:
    s = socket(AF_INET, SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]

# Returns connection info
def getClosest(hashedKey: int) -> Tuple[str, int]:
    closest = Fingers["self"]
    for key, value in Fingers.items():
        # update closest if value is closer than closest without
        # going past the hashed key
        if hashedKey - value[1] >= 0 and hashedKey - value[1] < hashedKey - closest[1]:
            closest = value
    return closest[0]

def ownsData(hashedKey: int) -> bool:
    return getClosest(hashedKey)[0] == Fingers["self"][0] and getClosest(hashedKey)[1] == Fingers["self"][1] 

#####################################################


################# Initial setup #####################
selfPort = 12345
sock = socket(AF_INET, SOCK_STREAM)
sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
sock.bind( ('', selfPort) )
sock.listen(16)

selfIP = getLocalIPAddress()
selfConn = (selfIP, selfPort)
selfLocation = getHashIndex(selfConn)

# value is a tuple of (connection info, location in DHT)
Fingers = {
    "self": None,
    "prev": None,
    "next": None,
    "finger1": None,
    "finger2": None,
    "finger3": None,
    "finger4": None
}

dhtData = {}
#####################################################


#################### Start New DHT #################
def createDHT() -> None:
    print("Starting a new DHT")
    # Update finger table
    for key in Fingers:
        Fingers[key] = (selfConn, selfLocation)
####################################################


################# Locate Protocol #####################
"""
[Self->Peer] LOCATE
[Self->Peer] HashedKey
[Peer->Self] PeerAddress
"""

def locate(data: str) -> Tuple[str, int]:
    # Get the hashed key of data and the closest peer from finger table
    hashedKey = getHashKey(data)
    closest = getClosest(hashedKey)
    # Return the connection info for the closest peer
    return locate_helper(closest, hashedKey)

def locate_helper(peerConn, hashedKey: int) -> Tuple[str, int]:
    # Connect to the peer
    conn = socket(AF_INET, SOCK_STREAM)
    conn.connect(peerConn)

    # Send command
    conn.sendall("LOCATE\n".encode())
    # Send Hashed Key
    conn.sendall((str(hashedKey) + '\n').encode())
    # Recieve Peer Address
    ip, port = get_line(conn).split(':')
    port = int(port)
    
    # If new connection is same as the person you asked
    # you know they own the data
    if peerConn[0] == ip and peerConn[1] == port:
        return (ip, port)
    # Otherwise try again with the new connection info
    else:
        return locate_helper((ip, port), hashedKey)

def handle_locate(conn) -> None:
    # Recieve Hashed Key
    hashedKey = int(get_line(conn))
    # Get closest peer
    closest = getClosest(hashedKey)
    closest_str = f"{closest[0]}:{closest[1]}\n"
    # Send closest peer
    conn.sendall(closest_str.encode())
#######################################################


#################### Get Protocol #################
def get():
    """
    [Self->Peer] GET
    [Self->Peer] HashedKey
    [Peer->Self] Acknowledgement of ownership of HashedKey Space Bail out if answer is ‘0’\n
    [Peer->Self] integer len(ValueData)
    [Peer->Self] byteArray of ValueData
    """
    pass
####################################################


#################### Insert Protocol #################
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
######################################################


#################### Remove Protocol #################
def remove():
    """
    [Self->Peer] REMOVE
    [Self->Peer] HashedKey
    [Peer->Self] Acknowledgement of ownership of HashedKey Space Bail out if answer is ‘0’\n
    [Peer->Self] Acknowledgement of successful REMOVE
    Also acknowledge ‘1’ if key didn’t exist. Remove didn’t fail.
    """
    pass
######################################################


#################### Contains Protocol #################
def contains():
    """
    [Self->Peer] CONTAINS
    [Self->Peer] HashedKey
    [Peer->Self] Acknowledgement of ownership of HashedKey Space Bail out if answer is ‘0’\n
    [Peer->Self] Acknowledgement of having entry
    """
    pass
########################################################


################# Connect Protocol #####################
def connect(peerIP, peerPort):
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

    # Connect to the peer
    conn = socket(AF_INET, SOCK_STREAM)
    conn.connect((peerIP, peerPort))

    # Send the connect protocol information 
    conn.sendall(b'CONNECT\n')
    conn.sendall((hashedKey + '\n').encode())

    # Wait for response from the peer
    ack = get_line(conn)
    if ack != '1':
        print("Target does not own space.")
        conn.close()
        return False

    # Get number of entries
    numEntries = int(get_line(conn))
    entries = []
    for i in range(numEntries):
        key = get_line(conn)
        itemLen = int(get_line(conn))
        item = recvall(conn, itemLen)
        entries.append((key, item))

    # Get address of the next peer
    next = get_line(conn)
    conn.close()

    # Update next's prev
    update_prev(next, f"{selfIP}:{selfPort}")

    # Give the previous peer our information
    conn = socket(AF_INET, SOCK_STREAM)
    conn.connect((peerIp, peerPort))
    conn.sendall((f"{selfIP}:{selfPort}\n").encode())
    conn.close()

    print("Connnect complete.")
    return True

def handle_connect(conn, addr):
    try:
        hashedKey = int(get_line(conn))
        print(f"Connect request from key: {hashedKey}")

        selfKey = getHashIndex(tuple(map(str, peerInformation["address"].split(":"))))
        prevKey = getHashIndex(tuple(map(str, peerInformation["prev"].split(":")))) if peerInformation["prev"] else None

        owns = False
        if peerInformation["prev"] is None:
            owns = True
        elif prevKey < selfKey:
            owns = prevKey < hashedKey <= selfKey
        else:
            owns = hashedKey > prevKey or hashedKey <= selfKey

        if not owns:
            print("Does not own space for this key. Rejecting.")
            conn.sendall(b'0\n')
            conn.close()
            return

        conn.sendall(b'1\n')

        numEntries = len(dhtData)
        conn.sendall(f"{numEntries}\n".encode())
        for key, val in dhtData.items():
            conn.sendall(f"{key}\n".encode())
            conn.sendall(f"{len(val)}\n".encode())
            conn.sendall(val)

        if peerInformation["next"]:
            conn.sendall((peerInformation["next"] + '\n').encode())
        else:
            conn.sendall(b"none\n")

        newPeerAddr = get_line(conn)
        print(f"New peer connected: {newPeerAddr}")
        peerInformation["prev"] = newPeerAddr
        print("Prev updated")

    except Exception as e:
        print(f"Error in handle_connect: {e}")
########################################################


################# Disconnect Protocol #####################
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
###########################################################


################# Update Prev Protocol #####################
def update_prev(nextAddr, selfAddr):
    """
    [Self->Next] UPDATE_PREV
    [Self->Next] PeerAddress of self
    [Next->Self] Acknowledgement
    """
    host, port = nextAddr.split(':')
    port = int(port)

    try:
        conn = socket(AF_INET, SOCK_STREAM)
        conn.connect((host, port))

        conn.sendall(b"UPDATE_PREV\n")
        conn.sendall((selfAddr + '\n').encode())

        ack = get_line(conn)
        conn.close()

        if ack == '1':
            print(f"Successfully udpates prev for {nextAddr}.")
            return True
        else:
            print(f"Failed to update prev for {nextAddr}.")
            return False
    except Exception as e:
        print(f"Error: {e}")
        return False

def handle_update_prev(conn, update_prev):
    try:
        newPrev = get_line(conn)
        update = update_prev_finger(newPrev)

        if update:
            conn.sendall(b'1\n')
        else:
            conn.sendall(b'0\n')
    except Exception as e:
        print(f"Error: {e}")
        conn.sendall(b'0\n')
############################################################

def handle_connection(conn, addr):
    try:
        command = get_line(conn)
        print(f"Received command: {command} from {addr}")

        if command == "CONNECT":
            handle_connect(conn, addr)
        elif command == "UPDATE_PREV":
            handle_update_prev(conn, update_prev)
        elif command == "GET":
            # TODO:
            pass
        elif command == "INSERT":
            # TODO: 
            pass
        elif command == "REMOVE":
            # TODO:
            pass
        elif command == "CONTAINS":
            # TODO:
            pass
        elif command == "LOCATE":
            handle_locate(conn)
        elif command == "DISCONNECT":
            # TODO: 
            pass
        else:
            print(f"Unknown command: {command}")
            conn.sendall(b'ERROR\n')

    except Exception as e:
        print(f"Error handling connection from {addr}: {e}")
    finally:
        conn.close()


def listener():
    while True:
        threading.Thread(target=handle_connection, args=(*sock.accept(),), daemon=True).start()

print("DHT Running...")
print("IP Address:", selfIP)
print("Listening on port:", selfPort)

try:
    if len(argv) >= 2:
        peerIP = argv[1]
        peerPort = argv[2]
        connect(peerIP, peerPort)
    else:
        createDHT()
        
    threading.Thread(target=listener, args=(), daemon=True).start()

    while True:
        command = input()
        if ' ' in command:
            action, data = command.split(' ', 1)
        else:
            action = command
            data = ''
        print(action)
        if action == "get":
            # TODO:
            pass
        elif action == "locate":
            locate(data)
        elif action == "insert":
            # TODO: 
            pass
        elif action == "remove":
            # TODO
            pass
        elif action == "contains":
            # TODO:
            pass
        elif action == "disconnect":
            # TODO: 
            pass
        else:
            print(f"Unknown command: {command}")
except KeyboardInterrupt:
    print("\n DHT Shutting Down...")
    sock.close()
