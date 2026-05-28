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
parser.add_argument("local_port", help="The port you want to use. Recommened is 5000", type=int)
parser.add_argument("remote_port", help="The host's port", type=int)
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



# one peer will be the listener and the other the connecter. Depends on who is faster
def listen(host, port, win, message): # When you debugging code nd lowkey realise that you're gay
    server = socket.socket() 
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # When script is closed, this just tells computer to recycle the port that was being used. Normally, there is like a 30 second cooldown of some sort so this just skips it.
    server.bind((host, port))
    server.listen(1)
    message.append(f"[*]Listening on {host}:{port}")
    conn, addr = server.accept() 
    message.append(f"[*]Incoming connection from {addr[0]}:{addr[1]}")
    draw_messages(win, message)
    server.close() # THis is to stop listening if it already got a peer. Might change later to accomodate multiple peers at the same time. Groupchat sort of thing.
    return conn

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

def race(host, local_port, remote_port, win, message): # This is to launch both listening and connecting and whichever gets the peer first wins.(The loser is dumped in hot oil and force fed hummus through their anus)
    result = [] # But seriously, this is needed such that both peers can be both server and client
    done = threading.Event() # Threading mentioned (#*#)

    def listen_wrapper():
        sock = listen("0.0.0.0", local_port, win, message)
        result.append(sock)
        done.set()

    def connect_wrapper():
        sock = connect(host, remote_port, win, done, message)
        if sock:
            result.append(sock)
            done.set()
    listener = threading.Thread(target=listen_wrapper)
    connecter = threading.Thread(target=connect_wrapper)
    listener.daemon = True
    connecter.daemon = True
    listener.start() # THis calls both functions btw
    connecter.start()
    done.wait() # Won't continue until a peer has been heard or spoken to idk
    return result[0]

# This is used to append the amount of bytes in the message being sent to the start of it. i.e..[4 bytes][message]
def send_msg (sock, data):
    length = len(data).to_bytes(4, 'big')
    sock.sendall(length + data)

# This is to check the bytes the message is supposed to contain when received AND to output the full encrypted message
def recv_msg(sock):
    raw_length = recv_all(sock, 4)
    if raw_length == None:
        return None
    length = int.from_bytes(raw_length, 'big')
    return recv_all(sock, length)


def recv_loop(sock, derived_key, win, lock, messages): # Function to receive texts
   while True:
        try:
            recvd_rawmsg = recv_msg(sock)
            if recvd_rawmsg == None:
                messages.append("Peer has Disconnected!")
                with lock:
                    draw_messages(win, messages)
                break 
            mumbl = decrypt(derived_key, recvd_rawmsg)
            messages.append("Peer: " + mumbl.decode())
            with lock:
                draw_messages(win, messages)
        except OSError:
            messages.append("Connection Error. Peer may have disconnected.")
            with lock:
                draw_messages(win, messages)
            break
            
def send_loop(sock, derived_key, msg_win, input_win, lock, messages):
    current_txt = ""
    while True:
        ch = input_win.getch()
        if ch == 10: # 'Enter' is ch == 10. Backspace is ch==127. Random ahh number assignments
            if current_txt == "":
                continue
            if current_txt == "/bye": # This is the clean exit. Realised that Ctrl + C everytime is just sloppy work
                current_txt = "<<Your Peer has Disconnected!>>"
                msg = encrypt(derived_key, (bytes(current_txt, "utf-8")))
                send_msg(sock, msg)
                sock.close()
                sys.exit()
            msg = encrypt(derived_key, (bytes(current_txt, "utf-8")))
            send_msg(sock, msg) # sock stands for socket btw, not foot gloves. Refer to Main for the creation of 'sock'
            messages.append("Me: " + current_txt)
            current_txt = ""
            with lock:
                draw_messages(msg_win, messages)
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
    time.sleep(3)
    sock = race(host, local_port, remote_port, msg_win, messages)
    private_key, public_key = keygen()
    derived_key = key_exchange(sock, private_key, public_key)
    chat_hash = hashlib.sha256(derived_key).hexdigest()
    trun_chat_hash = chat_hash[:6]
    messages.append(f"<<<Your chat hash code is <{trun_chat_hash}>, ensure it matches with your peer before continuing chatting.>>>")
    with lock2:
        draw_messages(msg_win, messages)
    recv = threading.Thread(target=recv_loop ,args=(sock, derived_key, msg_win, lock2, messages))
    recv.daemon = True
    recv.start()
    send_loop(sock, derived_key, msg_win, input_win, lock2, messages)


curses.wrapper(lambda stdscr: main(stdscr, host, local_port, remote_port)) # lambda since the curses wrapper NEEDS the stdscr to be passed, but the user is'nt inputting that themselves, and its needed to start main too, yk?