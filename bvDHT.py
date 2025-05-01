from socket import *
from sys import argv
from typing import Tuple, Union
import threading
import hashlib

MAXHASH = 2**160 - 1

#################### Util Functions #################
def get_line(conn: socket) -> str:
    msg = b''
    while True:
        ch = conn.recv(1)
        msg += ch
        if ch == b'\n' or len(ch) == 0:
            break
    return msg.decode().strip()

def recvall(conn: socket, msgLength: int) -> bytes:
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

def update_prev_finger(peerAddr: Tuple[str, int]) -> bool:
    Fingers["prev"] = (peerAddr, getHashIndex(peerAddr))
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
        if not value:
            continue
        # update closest if value is closer than closest without
        # going past the hashed key
        if hashedKey >= value[1] and hashedKey >= closest[1]:
            closest = value if value[1] > closest[1] else closest
        elif hashedKey >= value[1] and hashedKey < closest[1]:
            closest = value
        elif hashedKey < value[1] and hashedKey < closest[1]:
            if (MAXHASH - value[1]) + hashedKey < (MAXHASH - closest[1]) + hashedKey:
                closest = value
    return closest[0]

def ownsData(hashedKey: int) -> bool:
    selfFinger = Fingers["self"]
    if Fingers["next"] == None:
        return False
    elif Fingers["next"][1] == selfFinger[1]:
        return True
    else:
        nextFinger = Fingers["next"]

    if hashedKey >= selfFinger[1] and hashedKey >= nextFinger[1]:
        return True if selfFinger[1] > nextFinger[1] else False
    elif hashedKey >= selfFinger[1] and hashedKey < nextFinger[1]:
        return True
    elif hashedKey < selfFinger[1] and hashedKey < nextFinger[1]:
        return (MAXHASH - selfFinger[1]) + hashedKey <= (MAXHASH - nextFinger[1]) + hashedKey
    return False

def updateFingers() -> None:
    for i in range(4):
        hashedKey = int(selfLocation + (MAXHASH / 5) * (i + 1))
        if hashedKey > MAXHASH:
            hashedKey -= MAXHASH
        peer = locate(hashedKey)
        peerLoc = getHashIndex(peer)
        Fingers[f"finger{i}"] = (peer, peerLoc)

def printFingers() -> None:
    for key, value in Fingers.items():
        if value:
            print(f"{key}- {value[0][0]}:{value[0][1]} at {value[1]}")

def printData() -> None:
    for key, value in dhtData.items():
        print(f"{key} : {value}")
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
    "finger0": None,
    "finger1": None,
    "finger2": None,
    "finger3": None
}

dhtData = {}
#####################################################


#################### Start New DHT #################
def createDHT() -> None:
    print("Starting a new DHT")
    # Update finger table
    Fingers["self"] = (selfConn, selfLocation)
    Fingers["next"] = (selfConn, selfLocation)
####################################################


################# Locate Protocol #####################
"""
[Self->Peer] LOCATE
[Self->Peer] HashedKey
[Peer->Self] PeerAddress
"""

def locate(data: Union[str, int], *args) -> Tuple[str, int]:
    # Get the hashed key of data
    if isinstance(data, int):
        hashedKey = data
    else:
        hashedKey = getHashKey(data)
    # If owns the data no need to look through finger table
    if ownsData(hashedKey):
        return selfConn
    # Get closest finger
    if len(args) == 1:
        closest = args[0]
    else:
        closest = getClosest(hashedKey)
    # Return the connection info for the closest peer
    return locate_helper(closest, hashedKey)

def locate_helper(peerConn: Tuple[str, int], hashedKey: int) -> Tuple[str, int]:
    # Connect to the peer
    conn = socket(AF_INET, SOCK_STREAM)
    conn.connect(peerConn)

    # Send command
    conn.sendall("LOCATE\n".encode())
    # Send Hashed Key
    conn.sendall((str(hashedKey) + '\n').encode())
    # Receive Peer Address
    ip, port = get_line(conn).split(':')
    port = int(port)
    conn.close()
    
    # If new connection is same as the person you asked
    # you know they own the data
    if peerConn[0] == ip and peerConn[1] == port:
        return (ip, port)
    # Otherwise try again with the new connection info
    else:
        return locate_helper((ip, port), hashedKey)

def handle_locate(conn: socket) -> None:
    # Receive Hashed Key
    hashedKey = int(get_line(conn))
    # Get closest peer
    closest = getClosest(hashedKey)
    closest_str = f"{closest[0]}:{closest[1]}\n"
    # Send closest peer
    conn.sendall(closest_str.encode())
#######################################################


#################### Get Protocol #################
"""
[Self->Peer] GET
[Self->Peer] HashedKey
[Peer->Self] Acknowledgement of ownership of HashedKey Space Bail out if answer is ‘0’\n
[Peer->Self] integer len(ValueData)
[Peer->Self] byteArray of ValueData
"""

def get(key: str) -> str:
    hashedKey = getHashKey(key)
    ack = None
    while ack != '1':
        # Get peer we think owns data
        peer = locate(hashedKey)

        # Connect to peer
        peerConn = socket(AF_INET, SOCK_STREAM)
        peerConn.connect(peer)

        # Send the connect protocol information 
        peerConn.sendall(b'GET\n')
        peerConn.sendall((str(hashedKey) + '\n').encode())

        # Get acknowledgement of ownership of space
        ack = get_line(peerConn)
        if ack != '1':
            peerConn.close()

    # Get length of data and data of that length
    dataSize = int(get_line(peerConn))
    if dataSize == 0:
        print("No data found...")
        data = ''
    else:
        data = recvall(peerConn, dataSize).decode()
        print(data)
    peerConn.close()
    return data

def handle_get(conn: socket) -> None:
    hashedKey = int(get_line(conn))
    # Send ack of ownership of space
    if not ownsData(hashedKey):
        conn.sendall(b'0\n')
        conn.close()
        return
    conn.sendall(b'1\n')

    # Send len of data followed by data. 0 if not found
    if hashedKey in dhtData:
        conn.sendall((str(len(dhtData[hashedKey])) + '\n').encode())
        conn.sendall(dhtData[hashedKey].encode())
    else:
        conn.sendall(b'0\n')
    conn.close()
####################################################


#################### Insert Protocol #################
"""
[Self->Peer] INSERT
[Self->Peer] HashedKey
[Peer->Self] Acknowledgement of ownership of HashedKey Space, Bail out if answer is ‘0’\n
[Self->Peer] integer len(ValueData)
[Self->Peer] byteArray of ValueData
[Peer->Self] Acknowledgement of successful INSERT
"""

def insert(key: str, data: str) -> bool:
    hashedKey = getHashKey(key)
    ack = None
    while ack != '1':
        # Get peer we think owns data
        peer = locate(hashedKey)

        # Connect to peer
        peerConn = socket(AF_INET, SOCK_STREAM)
        peerConn.connect(peer)

        # Send the connect protocol information 
        peerConn.sendall(b'INSERT\n')
        peerConn.sendall((str(hashedKey) + '\n').encode())

        # Get acknowledgement of ownership of space
        ack = get_line(peerConn)
        if ack != '1':
            peerConn.close()

    # Send length of data followed by data
    peerConn.sendall((str(len(data)) + '\n').encode())
    peerConn.sendall(data.encode())

    # Get ack of successful insert
    ack = get_line(peerConn)
    peerConn.close()
    if ack != '1':
        print("Error: issue inserting data")
        return False
    return True

def handle_insert(conn: socket) -> None:
    hashedKey = int(get_line(conn))
    # Send ack of ownership of space
    if not ownsData(hashedKey):
        conn.sendall(b'0\n')
        conn.close()
        return
    conn.sendall(b'1\n')

    # Get data
    dataSize = int(get_line(conn))
    data = recvall(conn, dataSize)

    # Put data into local storage
    dhtData[hashedKey] = data.decode()
    # Send ack of successful insertion
    conn.sendall(b'1\n')
    conn.close()
######################################################


#################### Remove Protocol #################
"""
[Self->Peer] REMOVE
[Self->Peer] HashedKey
[Peer->Self] Acknowledgement of ownership of HashedKey Space Bail out if answer is ‘0’\n
[Peer->Self] Acknowledgement of successful REMOVE
Also acknowledge ‘1’ if key didn’t exist. Remove didn’t fail.
"""

def remove(key: str) -> bool:
    hashedKey = getHashKey(key)
    ack = None
    while ack != '1':
        # Get peer we think owns data
        peer = locate(hashedKey)

        # Connect to peer
        peerConn = socket(AF_INET, SOCK_STREAM)
        peerConn.connect(peer)

        # Send the connect protocol information 
        peerConn.sendall(b'REMOVE\n')
        peerConn.sendall((str(hashedKey) + '\n').encode())

        # Get acknowledgement of ownership of space
        ack = get_line(peerConn)
        if ack != '1':
            peerConn.close()

    # Get ack of successful removal
    ack = get_line(peerConn)
    peerConn.close()
    if ack == '1':
        print("Successfully removed!")
        return True
    else:
        print(f"Error removing {key}")
        return False

def handle_remove(conn: socket) -> None:
    hashedKey = int(get_line(conn))
    # Send ack of ownership of space
    if not ownsData(hashedKey):
        conn.sendall(b'0\n')
        conn.close()
        return
    conn.sendall(b'1\n')

    # Remove data and send 1 if successful, 0 if not
    try:
        if hashedKey in dhtData:
            dhtData.pop(hashedKey)
        conn.sendall(b'1\n')
    except Exception as e:
        print(f"Error: {e}")
        conn.sendall(b'0\n')
    finally:
        conn.close()
######################################################


#################### Contains Protocol #################
"""
[Self->Peer] CONTAINS
[Self->Peer] HashedKey
[Peer->Self] Acknowledgement of ownership of HashedKey Space Bail out if answer is ‘0’\n
[Peer->Self] Acknowledgement of having entry
"""

def contains(key: str) -> bool:
    hashedKey = getHashKey(key)
    ack = None
    while ack != '1':
        # Get peer we think owns data
        peer = locate(hashedKey)

        # Connect to peer
        peerConn = socket(AF_INET, SOCK_STREAM)
        peerConn.connect(peer)

        # Send the connect protocol information 
        peerConn.sendall(b'CONTAINS\n')
        peerConn.sendall((str(hashedKey) + '\n').encode())

        # Get acknowledgement of ownership of space
        ack = get_line(peerConn)
        if ack != '1':
            peerConn.close()

    # Get ack of having data
    ack = get_line(peerConn)
    peerConn.close()
    if ack == '1':
        print("true")
        return True
    else:
        print("false")
        return False

def handle_contains(conn: socket) -> None:
    hashedKey = int(get_line(conn))
    # Send ack of ownership of space
    if not ownsData(hashedKey):
        conn.sendall(b'0\n')
        conn.close()
        return
    conn.sendall(b'1\n')

    # Send ack of having data
    if hashedKey in dhtData:
        conn.sendall(b'1\n')
    else:
        conn.sendall(b'0\n')
    conn.close()
########################################################


################# Connect Protocol #####################
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

def connect(peerIP: str, peerPort: int) -> None:
    # Put self in finger table
    Fingers["self"] = (selfConn, selfLocation)

    addrStr = "%s:%d" % selfConn
    ack = None
    while ack != '1':
        # Find your spot in the DHT
        closestPeer = locate(addrStr, (peerIP, peerPort))

        # Connect to the peer
        conn = socket(AF_INET, SOCK_STREAM)
        conn.connect(closestPeer)

        # Send the connect protocol information 
        conn.sendall(b'CONNECT\n')
        conn.sendall((str(selfLocation) + '\n').encode())

        # Get acknowledgement of ownership of space
        ack = get_line(conn)
        if ack != '1':
            conn.close()

    # Receive data
    numEntries = int(get_line(conn))
    for i in range(numEntries):
        key = get_line(conn)
        itemLen = int(get_line(conn))
        item = recvall(conn, itemLen)
        dhtData[key] = item

    # Get address of the next peer
    ip, port = get_line(conn).split(':')
    port = int(port)
    Fingers["next"] = ((ip, port), getHashIndex((ip, port)))

    # Give the previous peer our information
    conn.sendall((addrStr + "\n").encode())
    conn.close()

    update_prev_finger(closestPeer)

    # Update next's prev
    update_prev((ip, port))

    updateFingers()

def handle_connect(conn: socket):
    try:
        hashedKey = int(get_line(conn))
        print(f"\nConnect request from key: {hashedKey}")

        if not ownsData(hashedKey):
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

        if Fingers["next"]:
            nextConn = Fingers["next"][0]
            conn.sendall((f"{nextConn[0]}:{nextConn[1]}\n").encode())
        else:
            nextConn = Fingers["self"][0]
            conn.sendall((f"{nextConn[0]}:{nextConn[1]}\n").encode())

        ip, port = get_line(conn).split(':')
        port = int(port)
        Fingers["next"] = ((ip, port), getHashIndex((ip, port)))

    except Exception as e:
        print(f"Error in handle_connect: {e}")
########################################################


################# Disconnect Protocol #####################
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

def disconnect() -> None:
    print("Disconnecting from DHT...")

    # Transfer data to next peer
    next_peer = Fingers["next"]
    if next_peer and next_peer != Fingers["self"]:
        conn = socket(AF_INET, SOCK_STREAM)
        conn.connect(next_peer[0])

        # Send insert command for each entry
        for hashedKey, value in dhtData.items():
            conn.sendall(b'INSERT\n')
            conn.sendall((str(hashedKey) + '\n').encode())
            conn.sendall((str(len(value)) + '\n').encode())
            conn.sendall(value.encode())
            ack = get_line(conn)
            if ack != '1':
                print(f"Failed to transfer key {hashedKey} to next node.")
        conn.close()

        # Notify next node to update its prev pointer
        conn = socket(AF_INET, SOCK_STREAM)
        conn.connect(next_peer[0])
        conn.sendall(b'UPDATEPREV\n')
        conn.sendall(("%s:%d\n" % Fingers["prev"][0]).encode())
        conn.close()

    # Notify prev node to update its next pointer
    prev_peer = Fingers["prev"]
    if prev_peer and prev_peer != Fingers["self"]:
        conn = socket(AF_INET, SOCK_STREAM)
        conn.connect(prev_peer[0])
        conn.sendall(b'UPDATENEXT\n')
        conn.sendall(("%s:%d\n" % Fingers["next"][0]).encode())
        conn.close()

    # Clear finger table and data
    for key in Fingers.keys():
        Fingers[key] = None
    dhtData.clear()

    print("Disconnected.")
###########################################################


################# Update Prev Protocol #####################
"""
[Self->Next] UPDATE_PREV
[Self->Next] PeerAddress of self
[Next->Self] Acknowledgement
"""

def update_prev(nextAddr: Tuple[str, int]) -> None:
    try:
        conn = socket(AF_INET, SOCK_STREAM)
        conn.connect(nextAddr)

        conn.sendall(b"UPDATE_PREV\n")
        conn.sendall((f"{selfConn[0]}:{selfConn[1]}\n").encode())

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

def handle_update_prev(conn: socket):
    try:
        ip, port = get_line(conn).split(':')
        update = update_prev_finger((ip, int(port)))

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
            handle_connect(conn)
        elif command == "UPDATE_PREV":
            handle_update_prev(conn)
        elif command == "GET":
            handle_get(conn)
        elif command == "INSERT":
            handle_insert(conn)
        elif command == "REMOVE":
            handle_remove(conn)
        elif command == "CONTAINS":
            handle_contains(conn)
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

def print_help():
    print("Available commands:")
    print("/insert <key> <value>  - Insert a key-value pair into the DHT")
    print("/get <key>             - Retrieve the value for a key")
    print("/remove <key>          - Remove a key-value pair")
    print("/contains <key>        - Check if a key exists in the DHT")
    print("/disconnect            - Gracefully leave the DHT")
    print("/help                  - Show this help message")


def listener():
    while True:
        threading.Thread(target=handle_connection, args=(*sock.accept(),), daemon=True).start()

print("DHT Running...")
print("IP Address:", selfIP)
print("Listening on port:", selfPort)

try:
    if len(argv) >= 2:
        peerIP = argv[1]
        peerPort = int(argv[2])
        connect(peerIP, peerPort)
    else:
        createDHT()
        
    threading.Thread(target=listener, args=(), daemon=True).start()

    while True:
        command = input('>')
        if ' ' in command:
            action, data = command.split(' ', 1)
        else:
            action = command
            data = ''
        print(action)
        if action == "get":
            get(data)
        elif action == "locate":
            locate(data)
        elif action == "insert":
            key, value = data.split(',', 1)
            insert(key, value)
        elif action == "remove":
            remove(data)
        elif action == "contains":
            contains(data)
        elif action == "disconnect":
            # TODO: 
            pass
        ### Helpful function to test
        elif action == "updateFingers":
            updateFingers()
        elif action == "printFingers":
            printFingers()
        elif action == "getData":
            printData()
        elif action == "/help":
            print_help()
        else:
            print(f"Unknown command: {command}")
            print_help()
except KeyboardInterrupt:
    print("\n DHT Shutting Down...")
    sock.close()
