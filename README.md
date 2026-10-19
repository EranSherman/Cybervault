CyberVault - Secure Cloud Password Manager
A client-server password management application built in Python demonstrating TCP socket networking, multi-threading, Tkinter graphical user interfaces, and hybrid RSA-2048 and AES-256-CBC cryptography.

Project Requirements Verification
This project fulfills all technical and architectural requirements specified in the assignment guidelines:

Client-Server Architecture: Built with Python's socket module over TCP/IP (bind, listen, accept, send, recv) with UTF-8 encoding and decoding.

Multi-Threading: Uses the threading module on the server to handle multiple concurrent clients simultaneously without blocking.

Graphical User Interface (GUI): Built with Tkinter on both the client and server, utilizing Label, Entry, Button, Text, and Listbox components.

RSA Asymmetric Encryption: Uses 2048-bit RSA keys with OAEP and SHA-256 padding via the cryptography library to perform the initial handshake and securely exchange the session key.

AES Symmetric Encryption: Uses a 256-bit (32-byte) AES session key in CBC mode with a random 16-byte Initialization Vector (IV) and PKCS7 padding to encrypt all traffic between the client and server, as well as stored vault data.

Password Key Derivation: Implements PBKDF2HMAC with SHA-256 and random salts for master password authentication.

How to Run the Project
1. Clone the Repository
Open PowerShell or Terminal and run:

cd $HOME/Desktop
git clone https://github.com/EranSherman/Cybervault.git
cd Cybervault

2. Install Dependencies
   
pip install -r requirements.txt

4. Start the Server (Terminal 1)
python server.py
Keep this terminal and the server monitor window open.

5. Start the Client (Terminal 2)
Open a second terminal window and run:

cd $HOME/Desktop/Cybervault
python client.py

Project Structure
crypto_utils.py - RSA-2048, AES-256-CBC, PBKDF2HMAC, and socket framing functions.

server.py - Multi-threaded TCP server, encrypted storage handler, and Tkinter admin monitor.

client.py - Tkinter client GUI for user authentication and encrypted credential management.

requirements.txt - Required Python dependencies (cryptography).
