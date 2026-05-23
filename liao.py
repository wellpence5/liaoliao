import socket
import threading
import time

def listen(host, port):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(1)
    print(f"[*]Listening on {host}:{port}")
    conn, addr = server.accept()
    print(f"[*]Incoming connection from {addr[0]}:{addr[1]}")
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
            time.sleep(1)
    
#conn = listen("0.0.0.0", 5000)
connect("localhost", 5000)
#print("Got  connection!", conn)