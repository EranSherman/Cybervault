import os
import struct
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


# --- RSA Encryption (Asymmetric) ---
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def rsa_encrypt(public_key, message: bytes) -> bytes:
    ciphertext = public_key.encrypt(
        message,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    plaintext = private_key.decrypt(
        ciphertext,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def serialize_public_key(public_key) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_public_key(pem_bytes: bytes):
    return serialization.load_pem_public_key(
        pem_bytes,
        backend=default_backend()
    )


# --- AES Encryption (Symmetric) ---
def generate_aes_key() -> bytes:
    # 256-bit AES key (32 bytes)
    return os.urandom(32)


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    # 16-byte random Initialization Vector (IV) for each encryption
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext


def aes_decrypt(key: bytes, ciphertext_with_iv: bytes) -> bytes:
    iv = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


# --- Password Hashing with PBKDF2HMAC ---
def hash_master_password(password: str, salt: bytes = None) -> tuple[str, str]:
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    derived_key = kdf.derive(password.encode('utf-8'))
    return salt.hex(), derived_key.hex()


# --- TCP Socket Framing (send / recv with 4-byte length prefix) ---
def send_msg(sock, data: bytes):
    header = struct.pack("!I", len(data))
    sock.send(header + data)


def recv_msg(sock) -> bytes:
    raw_len = _recv_exact(sock, 4)
    if not raw_len:
        return b""
    msg_len = struct.unpack("!I", raw_len)[0]
    return _recv_exact(sock, msg_len)


def _recv_exact(sock, num_bytes: int) -> bytes:
    buf = b""
    while len(buf) < num_bytes:
        chunk = sock.recv(num_bytes - len(buf))
        if not chunk:
            return b""
        buf += chunk
    return buf
