This is the start of my encrypted terminal p2p chat
This requires two main pillars;
1. Networking
2. Encryption

1. Networking
  -Sockets; Listen and transmit from a port
  -TCP; Ensure no data is lost
  -Asyncronous Programming (asyncio); listen for input and incoming messages at the same time

2. Cryptography
  -Handshake (Asymmetric)
    - X25519(ECDH); Exchange publis keys on open connection
    - Key Derivation
- Message flow (Symmetric)
    - AES-256-GCM
    - Encryption/Decryption; use shared secret before sending and vice-versa
    - Integrity(SHA256); Hashing to ensure no tampering
