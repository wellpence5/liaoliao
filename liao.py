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

def keygen(): # Function to generate the public and private keys
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return (private_key, public_key)

def key_exchange(sock, private_key, public_key): #Function to exchange keys with peer
    serialized_key = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw) # Serializing the key to bytes to push it through the socket
    sock.sendall(serialized_key)
    peer_serialized_key = sock.recv(4096) # Receiving the peer's public key. 4096 means its a byte btw
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

listenLog = [] 
host = sys.argv[1] # Reads the arguments provided when you launched this script
local_port = int(sys.argv[2])
remote_port = int(sys.argv[3])

def listen(host, port): # When you debugging code nd lowkey realise that you're gay
    server = socket.socket() 
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # When script is closed, this just tells computer to recycle the port that was being used. Normally, there is like a 30 second cooldown of some sort so this just skips it.
    server.bind((host, port))
    server.listen(1)
    print(f"[*]Listening on {host}:{port}")
    conn, addr = server.accept() 
    print(f"[*]Incoming connection from {addr[0]}:{addr[1]}")
    listenLog.append(addr)
    server.close() # THis is to stop listening if it already got a peer. Might change later to accomodate multiple peers at the same time. Groupchat sort of thing.
    return conn

def connect(host, port):
    while True: 
        try:
            soc = socket.socket()
            soc.connect((host, port))
            print(f"Connected to {host}:{port}")
            return soc
        except ConnectionRefusedError: # This error is gotten when the peer is'nt listning(Has no open port)
            soc.close()
            print("Retrying....")
            time.sleep(10) # The number can be random. Its just the time taken to timeout

def race(host, local_port, remote_port): # This is to launch both listening and connecting and whichever gets the peer first wins.(The loser is dumped in hot oil and force fed hummus through their anus)
    result = [] # But seriously, this is needed such that both peers can be both server and client
    done = threading.Event() # Threading mentioned (#*#)

    def listen_wrapper():
        sock = listen("0.0.0.0", local_port)
        result.append(sock)
        done.set()

    def connect_wrapper():
        sock = connect(host, remote_port)
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


def recv_loop(sock, derived_key, win, lock, messages): # Function to receive texts
   while True:
       mumbl = decrypt(derived_key, (sock.recv(4096)))
       if mumbl == b"":
           messages.append("Peer has Disconnected!") # If nothing was sent(Like literally 0 bytes) it means the other guy died :c
           with lock:
               draw_messages(win, messages)
           break
       messages.append(mumbl.decode())
       with lock:
           draw_messages(win, messages)

def send_loop(sock, derived_key, win, lock, messages):
    current_txt = ""
    while True:
        ch = win.getch()
        if ch == 10: # 'Enter' is ch == 10. Backspace is ch==127. Random ahh number assignments
            msg = encrypt(derived_key, (bytes(current_txt, "utf-8")))
            sock.send(msg) # sock stands for socket btw, not foot gloves
            messages.append(current_txt)
            current_txt = ""
            with lock:
                draw_messages(win, messages)
                draw_input(win, "")
        elif ch == 127:
            current_txt = current_txt[:-1]
            with lock:
                draw_input(win, "Me: " + current_txt)
        else:
            current_txt +=  chr(ch)
            with lock:
                draw_input(win, "Me: " + current_txt)
            
    
def main(stdscr, host, local_port, remote_port): # main
    height, width = stdscr.getmaxyx()
    msg_win = curses.newwin(height - 3, width, 0, 0)
    input_win = curses.newwin(3, width, height - 3, 0)
    sock = race(host, local_port, remote_port)
    private_key, public_key = keygen()
    derived_key = key_exchange(sock, private_key, public_key)
    lock2 = threading.Lock()
    messages = []
    recv = threading.Thread(target=recv_loop ,args=(sock, derived_key, msg_win, lock2, messages))
    recv.start()
    send_loop(sock, derived_key, input_win, lock2, messages)





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


curses.wrapper(lambda stdscr: main(stdscr, host, local_port, remote_port))