import os
import socket
import threading
import time
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM 
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

def keygen():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return (private_key, public_key)

def key_exchange(sock, private_key, public_key):
    serialized_key = public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    sock.sendall(serialized_key)
    peer_serialized_key = sock.recv(4096)
    peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_serialized_key)
    shared_key = private_key.exchange(peer_public_key)
    derived_key =  HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b"chat"
    ).derive(shared_key)
    return derived_key












listenLog = []
host = sys.argv[1]
local_port = int(sys.argv[2])
remote_port = int(sys.argv[3])

def listen(host, port):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    print(f"[*]Listening on {host}:{port}")
    conn, addr = server.accept()
    print(f"[*]Incoming connection from {addr[0]}:{addr[1]}")
    listenLog.append(addr)
    server.close()
    return conn

def connect(host, port):
    while True:
        try:
            soc = socket.socket()
            soc.connect((host, port))
            print(f"Connected to {host}:{port}")
            return soc
        except ConnectionRefusedError:
            soc.close()
            print("Retrying....")
            time.sleep(10)

def race(host, local_port, remote_port):
    result = []
    done = threading.Event()

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
    listener.start()
    connecter.start()
    done.wait()
    return result[0]

def recv_loop(sock):
   while True:
       mumbl = sock.recv(4096)
       if mumbl == b"":
           print("Connected peer has disconnected.")
           break
       print (mumbl.decode())

def send_loop(sock):
    while True:
        msg = bytes(input(), "utf-8")
        if msg == b"":
            continue
        sock.send(msg)
    
def main(host, local_port, remote_port):
    sock = race(host, local_port, remote_port)
    recv = threading.Thread(target=recv_loop ,args=(sock,))
    recv.start()
    send_loop(sock)

main(host, local_port, remote_port)