import os
import socket
import threading
import time
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM 
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
import curses
from curses import wrapper
import argparse
import hashlib

# Better way to parse the arguments entered.
parser = argparse.ArgumentParser(prog="liao.py", usage="%(prog)s [host] [local_port] [remote_port]")
parser.add_argument("host", help="The remote host you are connecting to.")
parser.add_argument("--local_port", "-l", help="The port you want to use. Default is 5000", type=int, default=5000)
parser.add_argument("--remote_port", "-r", help="The host's port. Default is 5000", type=int, default=5000) 
argus = parser.parse_args()
host = argus.host
local_port = argus.local_port
remote_port = argus.remote_port

# There are 2 windows; The message window an the input window.
def draw_messages(win, messages):
    win.clear()
    height, width = win.getmaxyx()
    visible = messages[-(height):]
    for i, msg in enumerate(visible):
        win.addstr(i, 0, msg)
    win.refresh()

def draw_input(win, current_text):
    win.clear()
    height, width = win.getmaxyx()
    win.addstr(0, 0, "-"*width)
    win.addstr(1, 0, "> " + current_text)
    win.refresh()

# Realised that getting your ip is too much work, so this just tells you what your ip is.
def get_my_ip(win):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        error_msg = []
        error_msg.append("Please check your network interface!")
        draw_messages(win, error_msg)
        return "unavailable"


# This function is to ensure all bits sent are received and processed together. TCP may send bits at a time which ould inevitably bring errors when decrypting since it doesnt have the complete ciphertext.
def recv_all(sock, n):   
    total_chunk = b""
    while len(total_chunk) < n:
        chunk = sock.recv(n - len(total_chunk))
        if not chunk:
            return None # peer disconnected mid-receive
        total_chunk += chunk # Add value of gotten bits back to total
    return total_chunk

def keygen(): # Function to generate the public and private keys
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return (private_key, public_key)

def key_exchange(sock, private_key, public_key): #Function to exchange keys with peer
    serialized_key = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw) # Serializing the key to bytes to push it through the socket
    send_thread = threading.Thread(target=sock.sendall, args=(serialized_key,)) # To avoid deadlocks where one peer fails to initialize recv on time or network lags, leading to receiving a partial key
    send_thread.start()
    peer_serialized_key = recv_all(sock, 32) # Receiving the peer's public key. X25519 are always 32 bytes.
    send_thread.join(timeout=10)
    if send_thread.is_alive():
        raise RuntimeError("Key send failure. lol")
    if peer_serialized_key == None:
        raise ConnectionError("Peer disconnected during key exchange.")
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_serialized_key) # This is just deserializing from byte
    shared_key = private_key.exchange(peer_public_key)
    derived_key =  HKDF( # To convert the x25519 key into an AESGCM key. The internal encryptions use AESGCM and x25519 is only used for key sharing.
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"chat" ).derive(shared_key)
    return derived_key

def encrypt(key, plaintext): # Encrypt function
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext

def decrypt(key, data): # Decrypt Function
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext



def connect(host, port, win, done, message):
    while not done.is_set(): # If listen() on race, this stops connect() from running forever until its killed later by daemon.
        try:
            soc = socket.socket()
            soc.connect((host, port))
            message.append(f"[*]Connected to {host}:{port}")
            draw_messages(win, message)
            return soc
        except ConnectionRefusedError: # This error is gotten when the peer is'nt listning(Has no open port)
            soc.close()
            if done.is_set():
                return None
            message.append("Retrying....")
            draw_messages(win, message)
            time.sleep(2) # The number can be random. Its just the time taken for the timeout
    return None

#listen() was removed and placed inside listen_wrapper() in race()

def race(host, local_port, remote_port, win, message): # This is to launch both listening and connecting and whichever gets the peer first wins.(The loser is dumped in hot oil and force fed hummus through their anus)
    result = [] # But seriously, this is needed such that both peers can be both server and client
    done = threading.Event() # Threading mentioned (#*#)

    def listen_wrapper():# Only the relay_master will flag this. All connecting peers will use connect_wrapper()
        server = socket.socket() 
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, local_port))
        server.listen(1)
        message.append(f"[*]Listening on {host}:{local_port}")
        sock, addr = server.accept() 
        message.append(f"[*]Incoming connection from {addr[0]}:{addr[1]}")
        draw_messages(win, message)
        result.append((sock, True, server)) # I know other peers still hve their listen sockets open. This is'nt a bug but a **future feature**. 
        done.set()

    def connect_wrapper():
        sock = connect(host, remote_port, win, done, message) # Refer to connect()
        if sock:
            result.append((sock, False, None))
            done.set()
    
        
    listener = threading.Thread(target=listen_wrapper)
    connecter = threading.Thread(target=connect_wrapper)
    listener.daemon = True
    connecter.daemon = True
    listener.start() # THis calls both functions btw
    connecter.start()
    done.wait() # Won't continue until a peer has been heard or spoken to idk
    return result[0] #result contains a tuple. Jump to main() to see them in action

# This is used to append the amount of bytes in the message being sent to the start of it. i.e..[4 bytes][message]
def send_msg (sock, data):
    length = len(data).to_bytes(4, 'big')
    sock.sendall(length + data) # I might add more functionality here to include unique identifiers or usernames to also be appended to the message

# This is to check the bytes the message is supposed to contain when received AND to output the full encrypted message
def recv_msg(sock):
    raw_length = recv_all(sock, 4)
    if raw_length == None:
        return None 
    length = int.from_bytes(raw_length, 'big')
    return recv_all(sock, length) 

# This recv_loop is for other peers who arent the relay master. The relay master gets a special one just for them :D
def recv_loop(sock, derived_key, win, lock, messages): # Function to receive texts. This is happening at the same time as the main thread(send)
   while True: 
        try:
            recvd_rawmsg = recv_msg(sock)
            if recvd_rawmsg == None:
                with lock:
                    messages.append("Peer has Disconnected!") # recv_loop is in a constant background thread loop btw. so putting this in prevents appending bugs
                    draw_messages(win, messages) # I will change this when adding usernames, so for now only the RM(relay master) can see in detail who left
                break                           # I can't do it now because uhhhh no unique id is being carried with the message to show who the author is, all you know is someone suddenly died XoX
            mumbl = decrypt(derived_key, recvd_rawmsg)
            with lock:
                messages.append("Peer: " + mumbl.decode())
                draw_messages(win, messages)
        except OSError:
            with lock:# "What are all these locks for?" Two people cant write on the same book at the same time. This just waits for whoevers editing it to finish before they edit. to prevent errors. Also seen during viewing
                messages.append("Connection Error. Peer may have disconnected.")
                draw_messages(win, messages)
            break
            
def send_loop(sock, derived_key, msg_win, input_win, lock, messages):
    current_txt = ""
    while True:
        ch = input_win.getch() # ch stands for character since this looks at any key you press. So if you press "F", it gets pushed down the loop and restarts until you press "Enter"
        if ch == 10: # 'Enter' is ch == 10. Backspace is ch==127. Random ahh number assignments
            if current_txt == "":
                continue
            if current_txt == "/bye": # This is the clean exit. Realised that Ctrl + C everytime is just sloppy work
                current_txt = "<<Your Peer has Disconnected!>>"
                msg = encrypt(derived_key, (bytes(current_txt, "utf-8")))
                send_msg(sock, msg)
                sock.close()
                sys.exit()
            msg = encrypt(derived_key, (bytes(current_txt, "utf-8"))) # Encryption point
            send_msg(sock, msg) # sock stands for socket btw, not foot gloves. Refer to Main for the creation of 'sock'
            messages.append("Me: " + current_txt)
            current_txt = ""
            with lock:
                draw_messages(msg_win, messages)# This is to show you what sent to you as the sender. Rest assured that the other peer(s) see the same
                draw_input(input_win, "Me: ")
        elif ch == 127:
            current_txt = current_txt[:-1] # Just means to delete 1 item from the end
            with lock:
                draw_input(input_win, "Me: " + current_txt)
        else:
            current_txt +=  chr(ch)
            with lock:
                draw_input(input_win, "Me: " + current_txt) # Now this is used to constantly show you what you are writing down.
            
# This function isnt being called in main() or anywhere else for now btw
def determine_role(sock, is_master): # This is declared redundant and will be edited to be a better verification check
    if is_master == True:           # Lowkey just caused too many errors and i scrapped it for now since race() produces the boolean to show whether one os relay master or not
        sock.send(bytes([1]))
    else:
        if sock.recv(1) != bytes([1]):
            raise ConnectionError("Invalid handshake")
    return is_master

# This is only run by the relay master. It checks for any peer wanting to join the conversation. 
def listen_for_peers(win, message, peers, lock, server): # Only drawback is that the peer has to know who the relay master is and connect to them directly
    while True:                                     # But that will be fixed in a later update
        sock, addr = server.accept()
        with lock:
            message.append(f"Peer {addr} has joined.")
            draw_messages(win, message)
            peers_copy = peers.copy()
            for peer_addr, peer_data in peers_copy.items():# For loops just to tell everyone someone left. Still encrypted tho
                if peer_addr != addr:                   # Youre right, i should put these fucking for loops as its own function. Spent like 30 minutes for some stupid bug in one of them
                    conf_msg = f"Peer {addr} has joined"
                    group_msg = encrypt(peer_data["key"], (bytes(conf_msg, "utf-8")))
                    send_msg(peer_data["sock"], group_msg)
        private_key, public_key = keygen()
        derived_key = key_exchange(sock, private_key, public_key)
        with lock:
            # This is the peer dictionary that holds the peers unique identifier(sock) and key to actually send the encrypted message to them
            peers[addr] = {
                "sock": sock,
                "key": derived_key
            }
        recv = threading.Thread(target=relay_recv, args=(sock, addr, peers, lock, win, message))
        recv.daemon = True
        recv.start()


# Here, the message will be unencrypted and reencrypted to everyones unique encryption and sent to everyone. 
# This isn't a server but a relay. Nothing is stored but immediately sent. 
def relay_recv(sock, addr, peers, lock, win, message):
    while True:
        try:
            recvd_msg = recv_msg(sock)
            if recvd_msg == None:
                sock.close()
                with lock:
                    message.append(f"Peer {addr} has left.")
                    draw_messages(win, message)
                    peers_copy = peers.copy()
                    for peer_addr, peer_data in peers_copy.items():# For loops just to tell everyone someone left. Still encrypted tho
                        if peer_addr != addr:
                            error_msg = f"Peer {addr} has left"
                            group_msg = encrypt(peer_data["key"], (bytes(error_msg, "utf-8")))
                            send_msg(peer_data["sock"], group_msg)
                    del peers[addr]
                break
            decrypted_recvd_msg = decrypt(peers[addr]["key"], recvd_msg)
            with lock:
                message.append("Peer: " + decrypted_recvd_msg.decode()) # This will change to show username of sender. Later update tho
                draw_messages(win, message)
                peers_copy = peers.copy()
                for peer_addr, peer_data in peers_copy.items():
                    try:
                        if peer_addr != addr: # This is to skip the sender cause they already gonna see hat they sent. Refer to send_loop()
                            group_msg = encrypt(peer_data["key"], decrypted_recvd_msg)
                            send_msg(peer_data["sock"], group_msg)
                    except OSError:
                        peer_data["sock"].close()
                        message.append(f"Peer {peer_addr} has left.")
                        draw_messages(win, message)
                        del peers[peer_addr]
        except OSError:
            with lock:
                sock.close()
                message.append(f"Peer {addr} has left.")
                draw_messages(win, message)
                peers_copy = peers.copy()
                for peer_addr, peer_data in peers_copy.items():
                    if peer_addr != addr:
                        error_msg = f"Peer {addr} has left"
                        group_msg = encrypt(peer_data["key"], (bytes(error_msg, "utf-8")))
                        send_msg(peer_data["sock"], group_msg)
                del peers[addr]
            break

# The function carrying the constant mass sending
def mass_group_send(lock, peers, win, message, current_txt):
    with lock:
        peers_copy = peers.copy() # We make a copy because if it real one is being read while edited, it gives an error about some value changing
        for peer_addr, peer_data in peers_copy.items():
            try:
                group_msg = encrypt(peer_data["key"], (bytes(current_txt, "utf-8")))
                send_msg(peer_data["sock"], group_msg)
            except OSError:
                    peer_data["sock"].close()
                    message.append(f"Peer {peer_addr} has left.") # Gonna add that for loop here later
                    draw_messages(win, message)
                    del peers[peer_addr]

# relay masters send loop btw. Its only uniqueness is that it sends message to everyone connected, while the normal send_loop() sends to the relay master only.
def masters_send_loop(peer, lock, msg_win, input_win, message):
    current_txt = ""
    while True:
        ch = input_win.getch()
        if ch == 10: # 'Enter' is ch == 10. Backspace is ch==127. Random ahh number assignments
            if current_txt == "":
                continue
            if current_txt == "/bye": # This is the clean exit. Realised that Ctrl + C everytime is just sloppy work
                current_txt = "<<The Relay Master has left. Group has been deleted and your messages will no longer be sent.>>"
                mass_group_send(lock, peer, msg_win, message, current_txt) # FYI, if the relay master leaves, the group chat dies with it. Its a fail-safe of somesort. Not bug but *feature*
                with lock: 
                    for peer_addr, peer_data in peer.items(): # ive always hated for loops for some reason
                        peer_data["sock"].close()
                sys.exit()
            mass_group_send(lock, peer, msg_win, message, current_txt)
            message.append("Me: " + current_txt)
            current_txt = ""
            with lock:
                draw_messages(msg_win, message)
                draw_input(input_win, "Me: ")
        elif ch == 127:
            current_txt = current_txt[:-1] # Just means to delete 1 item from the end
            with lock:
                draw_input(input_win, "Me: " + current_txt)
        else:
            current_txt +=  chr(ch)
            with lock:
                draw_input(input_win, "Me: " + current_txt)


    

    

def main(stdscr, host, local_port, remote_port): # main. Calling the functions in order. Clean as hell ngl
    # Just initializing the disply windows
    height, width = stdscr.getmaxyx()
    msg_win = curses.newwin(height - 3, width, 0, 0)
    input_win = curses.newwin(3, width, height - 3, 0)
    messages = []
    lock2 = threading.Lock() 
    ip = get_my_ip(msg_win)
    messages.append(f"Your outbound ip address is {ip}. Please let your peer know for them to connect!")
    messages.append("Type '/bye' to exit the chat")
    with lock2:
        draw_messages(msg_win, messages)
    time.sleep(3) # This is here to mostly give you time to look at your ip address and reflect about your life choices
    sock, is_master, server = race(host, local_port, remote_port, msg_win, messages)
    role_bool = is_master # I was too lazy to switch out all out for another. And also a reminder to add a verification that peer has connected to relay master
    peers = {}
    private_key, public_key = keygen()
    if role_bool == True: # If you are the relay master, follow this route. Everyone else goes to else
        messages.append("You are the relay master now")
        with lock2:
            draw_messages(msg_win, messages)
        # This will be done for all peers in listen_for_peers()
        derived_key = key_exchange(sock, private_key, public_key)
        addr = sock.getpeername()
        peers[addr] = {
            "sock": sock,
            "key": derived_key
        }
        # Setting up threads to run alongside main thread
        relay_recver = threading.Thread(target=relay_recv, args=(sock, addr, peers, lock2, msg_win, messages))
        peer_listener = threading.Thread(target=listen_for_peers, args=(msg_win, messages, peers, lock2, server))
        relay_recver.daemon = True
        peer_listener.daemon = True
        relay_recver.start()
        peer_listener.start()
        masters_send_loop(peers, lock2, msg_win, input_win, messages) # This is what i called the main thread btw
    else: # Hi everyone else
        derived_key = key_exchange(sock, private_key, public_key)
        # Chat hash will be revised as it is now useless. 
        #chat_hash = hashlib.sha256(derived_key).hexdigest()
        #trun_chat_hash = chat_hash[:6]
        #messages.append(f"<<<Your chat hash code is <{trun_chat_hash}>, ensure it matches with your peer before continuing chatting.>>>")
        #with lock2:
        #    draw_messages(msg_win, messages)
        recv = threading.Thread(target=recv_loop ,args=(sock, derived_key, msg_win, lock2, messages))
        recv.daemon = True
        recv.start()
        send_loop(sock, derived_key, msg_win, input_win, lock2, messages)


curses.wrapper(lambda stdscr: main(stdscr, host, local_port, remote_port)) # lambda since the curses wrapper NEEDS the stdscr to be passed, but the user is'nt inputting that themselves, and its needed to start main too, yk?