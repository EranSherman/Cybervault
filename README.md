# CyberVault - Secure Cloud Password Manager (RSA-2048 + AES-256)

A client-server password manager in Python demonstrating hybrid cryptography (`RSA` + `AES-CBC`), `PBKDF2HMAC` password hashing, multi-threaded TCP sockets, and `Tkinter` GUIs.

## Security Architecture
1. **RSA-2048 Key Exchange (Handshake)**: Upon TCP connection, the server sends its RSA Public Key. The client generates a 256-bit AES session key, encrypts it using RSA-OAEP (SHA-256), and transmits it to the server.
2. **AES-256-CBC Encrypted Transport**: Every request and response is encrypted with AES-256-CBC using a unique 16-byte random IV and PKCS7 padding.
3. **PBKDF2HMAC Authentication & Encrypted Storage**: Master passwords are salted and hashed with 100,000 iterations of PBKDF2-HMAC-SHA256, and vault secrets are stored encrypted with AES-256 on disk (`vault_db.json`).

## Running the Project
1. Install dependencies: `pip install -r requirements.txt`
2. Run the server: `python server.py`
3. Run one or more clients: `python client.py`
