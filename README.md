# liao — encrypted P2P terminal chat

A minimal encrypted peer-to-peer chat that runs in the terminal. No servers, no accounts, no stored keys. Built from scratch in Python.

## How it works

Two pillars:

### 1. Networking
- **TCP sockets** — reliable, ordered transmission with no data loss
- **Symmetric connection race** — both peers listen and connect simultaneously, whoever lands first wins. No designated server or client.
- **Threading** — separate threads for sending and receiving so neither blocks the other

### 2. Cryptography
- **X25519 key exchange** — both peers generate a fresh keypair on every session and exchange public keys over the open connection
- **HKDF (SHA-256)** — derives a clean AES-256 key from the raw shared secret
- **AES-256-GCM** — encrypts every message with a random nonce. GCM provides both encryption and tamper detection.
- **Forward secrecy** — keys are never stored. Every session generates new keys, so past sessions can't be decrypted even if a machine is compromised.

## Usage

Install dependencies:
pip install -r requirements.txt

Both peers run the same command:
python3 liao.py <peer_ip> <local_port> <remote_port>

Example — two machines on the same network:

Machine A:
python3 liao.py 192.168.1.10 5000 5001
Machine B:
python3 liao.py 192.168.1.9 5001 5000

## Known limitations
- No authentication — a man-in-the-middle could intercept the key exchange
- No message framing — may misbehave on unreliable or high-latency connections
- No replay attack protection