# liao — encrypted P2P terminal chat

A minimal encrypted peer-to-peer chat application that runs in the terminal.
No servers, no accounts, no stored keys. Built from scratch in Python.

## Features

- **End-to-end encryption** — every message is encrypted with AES-256-GCM before
  it leaves your machine
- **Forward secrecy** — fresh X25519 keypairs are generated every session; past
  sessions can't be decrypted even if a machine is later compromised
- **Symmetric connection race** — both peers listen and connect simultaneously;
  whoever establishes a connection first becomes the Relay Master, eliminating the
  need for a designated server
- **Group chat via relay** — the Relay Master temporarily decrypts and re-encrypts
  each message per peer using that peer's unique derived key, so a compromised
  peer doesn't expose the rest of the group
- **Terminal UI** — split-pane curses interface with a message window and live
  input window

## How it works

### Networking

- TCP sockets ensure reliable, ordered, lossless delivery
- Both peers simultaneously listen on a local port and attempt to connect to the
  remote port; whichever succeeds first wins the race
- Send and receive run on separate threads so neither blocks the other
- Messages are length-prefixed (`[4-byte length][payload]`) to guarantee full
  ciphertext is reconstructed before decryption

### Cryptography

| Step | Primitive | Purpose |
|---|---|---|
| Key exchange | X25519 | Ephemeral Diffie-Hellman over the open connection |
| Key derivation | HKDF-SHA-256 | Derives a 32-byte AES key from the raw shared secret |
| Encryption | AES-256-GCM | Encrypts each message with a random 12-byte nonce; provides both confidentiality and tamper detection |

### Group chat and the Relay Master

The first peer to accept an incoming connection becomes the **Relay Master**. All
other peers connect directly to the Relay Master rather than to each other.

When a message arrives at the Relay Master it is:
1. Decrypted using the sender's unique derived key
2. Re-encrypted individually for every other peer using their own derived key
3. Forwarded to each peer

This means a compromised peer's key cannot decrypt anyone else's messages. The
tradeoff is that the Relay Master is a point of trust — messages pass through it
in plaintext momentarily. If the Relay Master disconnects, the group closes and
all in-memory keys are discarded.

## Requirements

- Python 3.8+
- `cryptography`
- `windows-curses` (Windows only)

Install dependencies:
pip install -r requirements.txt

## Usage

Both peers run the same command:
python3 liao.py <peer_ip> [--local_port PORT] [--remote_port PORT]

### Arguments

| Argument | Flag | Default | Description |
|---|---|---|---|
| `host` | (positional) | — | The remote peer's IP address |
| `--local_port` | `-l` | 5000 | Local port to listen on |
| `--remote_port` | `-r` | 5000 | Remote port to connect to |

### Example — two machines on a local network

**Machine A** (`192.168.1.10`):
python3 liao.py 192.168.1.9 -l 5000 -r 5001

**Machine B** (`192.168.1.9`):
python3 liao.py 192.168.1.10 -l 5001 -r 5000

### Example — group chat (three peers)

Machine A becomes Relay Master when the first connection arrives. B and C both
point their `host` argument at A.

**Machine A** (`192.168.1.10`):
python3 liao.py 192.168.1.9 -l 5000 -r 5001

**Machine B** (`192.168.1.9`):
python3 liao.py 192.168.1.10 -l 5001 -r 5000

**Machine C** (`192.168.1.11`):
python3 liao.py 192.168.1.10 -l 5002 -r 5000

### In-chat commands

| Command | Action |
|---|---|
| `/bye` | Send a disconnect notice to all peers and exit cleanly |

## Security notes

- Keys are never written to disk; they exist only in memory for the duration of
  the session
- The Relay Master temporarily holds plaintext during the re-encryption step —
  choose your Relay Master accordingly, or connect early to a trusted peer to
  influence who wins the race
- No authentication of peer identity is implemented yet; the key exchange proves
  that both sides derived the same secret, but does not verify *who* is on the
  other end

## Planned improvements

- Peer usernames and unique message attribution
- Relay Master handover on disconnect so the group survives
- Identity verification / peer authentication
- Configurable relay vs. mesh topology