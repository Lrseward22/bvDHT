from socket import *
import threading
import hashlib

def get_line(conn):
    msg = b''
    while True:
        ch = conn.recv(1)
        msg += ch
        if ch == b'\n' or len(ch) == 0:
            break
    return msg.decode().strip()

def getHashIndex(addr):
    b_addrStr = ("%s:%d" % addr).encode()
    return int.from_bytes(hashlib.sha1(b_addrStr).digest(), byteorder="big")

def recvall(conn, msgLength):
    msg = b''
    while len(msg) < msgLength:
        retVal = conn.recv(msgLength - len(msg))
        msg += retVal
        if len(retVal) == 0:
            break    
    return msg

peerInformation = {
    "prev": None,
    "next": None,
    "address": None,
}

dhtData = {}


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

def connect(selfIP, selfPort, peerAddr):
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

    # Store our address and hash it
    selfAddr = (selfIP, selfPort)
    hashedKey = str(getHashIndex(selfAddr))

    # Get the peer address information
    host, port = peerAddr.split(':')
    port = int(port)

    # Connect to the peer
    conn = socket(AF_INET, SOCK_STREAM)
    conn.connect((host, port))

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
    conn.connect((host, port))
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
        update = update_prev(newPrev)

        if update:
            conn.sendall(b'1\n')
        else:
            conn.sendall(b'0\n')
    except Exception as e:
        print(f"Error: {e}")
        conn.sendall(b'0\n')

def update_prev(peerAddr):
    print("Updating prev peer.")
    peerInformation["prev"] = peerAddr
    return True

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
            # TODO: 
            pass
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


def listener(server_socket):
    while True:
        conn, addr = server_socket.accept()
        threading.Thread(target=handle_connection, args=(conn, addr)).start()

# Initial setup
port = 12345
socket = socket(AF_INET, SOCK_STREAM)
socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
socket.bind( ('', port) )
socket.listen(16)

print("DHT Running...")
print("Listening on port:", port)

try:
    listener(socket)
except KeyboardInterrupt:
    print("\n DHT Shutting Down...")
    socket.close()
