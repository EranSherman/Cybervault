import os
import json
import socket
import threading
import tkinter as tk
from datetime import datetime

from crypto_utils import (
    generate_rsa_keys,
    serialize_public_key,
    rsa_decrypt,
    generate_aes_key,
    aes_encrypt,
    aes_decrypt,
    hash_master_password,
    send_msg,
    recv_msg,
)

HOST = "127.0.0.1"
PORT = 6543
DB_FILE = "vault_db.json"
SERVER_KEY_FILE = "server_master.key"


class CyberVaultServerGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("CyberVault Server - Security & Network Monitor")
        self.root.geometry("760x540")
        self.root.configure(bg="#181825")

        # 1. Initialize RSA Keys for Handshake & AES Key for Disk Storage
        self.rsa_priv_key, self.rsa_pub_key = generate_rsa_keys()
        self.rsa_pub_pem = serialize_public_key(self.rsa_pub_key)
        self.storage_aes_key = self._load_or_create_storage_key()

        # 2. Server State & Thread Synchronization
        self.lock = threading.Lock()
        self.active_clients = 0
        self.db = self._load_db()

        self._build_gui()
        self._start_server()

    def _load_or_create_storage_key(self) -> bytes:
        if os.path.exists(SERVER_KEY_FILE):
            with open(SERVER_KEY_FILE, "rb") as f:
                return f.read()
        key = generate_aes_key()
        with open(SERVER_KEY_FILE, "wb") as f:
            f.write(key)
        return key

    def _load_db(self) -> dict:
        if os.path.exists(DB_FILE):
            try:
                with open(DB_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"users": {}}

    def _save_db(self):
        with open(DB_FILE, "w", encoding="utf-8") as f:
            json.dump(self.db, f, indent=4)

    def _build_gui(self):
        # Tkinter Label (Header)
        tk.Label(
            self.root,
            text=f"🛡️ CyberVault Encrypted Server | TCP {HOST}:{PORT}",
            font=("Segoe UI", 14, "bold"),
            bg="#181825",
            fg="#cdd6f4",
            pady=10,
        ).pack(fill=tk.X)

        self.status_label = tk.Label(
            self.root,
            text=f"Connected Clients: 0 | Registered Vaults: {len(self.db['users'])}",
            font=("Segoe UI", 10, "bold"),
            bg="#181825",
            fg="#a6e3a1",
        )
        self.status_label.pack(pady=(0, 8))

        # Tkinter Text (Live Security Log)
        log_frame = tk.Frame(self.root, bg="#181825", padx=15, pady=5)
        log_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(
            log_frame,
            text="Live RSA Handshake & AES-256 Traffic Logs:",
            font=("Segoe UI", 10, "bold"),
            bg="#181825",
            fg="#89b4fa",
            anchor="w",
        ).pack(fill=tk.X)

        self.log_text = tk.Text(
            log_frame,
            font=("Consolas", 9),
            bg="#11111b",
            fg="#cdd6f4",
            state="disabled",
            height=20,
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, pady=5)

        # Tkinter Button (Clear Logs)
        tk.Button(
            self.root,
            text="Clear Security Logs",
            font=("Segoe UI", 9, "bold"),
            bg="#313244",
            fg="#cdd6f4",
            command=self._clear_logs,
            padx=10,
            pady=4,
        ).pack(pady=(0, 12))

    def _clear_logs(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state="disabled")

    def log(self, message: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.root.after(0, self._append_log, f"[{ts}] {message}\n")

    def _append_log(self, text: str):
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, text)
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")
        self.status_label.config(
            text=f"Connected Clients: {self.active_clients} | Registered Vaults: {len(self.db['users'])}"
        )

    def _start_server(self):
        t = threading.Thread(target=self._AcceptLoop, daemon=True)
        t.start()

    def _AcceptLoop(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, PORT))
        server_sock.listen(5)
        self.log(f"Server listening on {HOST}:{PORT}. RSA-2048 key pair generated.")

        while True:
            client_sock, addr = server_sock.accept()
            with self.lock:
                self.active_clients += 1
            self.log(f"[+] Client connected from {addr[0]}:{addr[1]}")
            threading.Thread(
                target=self._handle_client, args=(client_sock, addr), daemon=True
            ).start()

    def _handle_client(self, client_sock: socket.socket, addr):
        authenticated_user = None
        try:
            # Step 1: RSA Handshake - Send Server RSA Public Key
            send_msg(client_sock, self.rsa_pub_pem)
            self.log(f"[{addr[1]}] Sent RSA-2048 Public Key to client.")

            # Step 2: Receive RSA-Encrypted AES-256 Session Key
            encrypted_aes_key = recv_msg(client_sock)
            if not encrypted_aes_key:
                return
            aes_session_key = rsa_decrypt(self.rsa_priv_key, encrypted_aes_key)
            self.log(
                f"[{addr[1]}] RSA Handshake complete! Established AES-256 key: {aes_session_key[:6].hex()}..."
            )

            # Step 3: Encrypted AES-256 Session Loop
            while True:
                encrypted_packet = recv_msg(client_sock)
                if not encrypted_packet:
                    break

                self.log(
                    f"[{addr[1]}] Encrypted AES Packet ({len(encrypted_packet)}B): {encrypted_packet[:20].hex()}..."
                )
                decrypted_json = aes_decrypt(aes_session_key, encrypted_packet).decode("utf-8")
                request = json.loads(decrypted_json)

                response, authenticated_user = self._process_request(
                    request, authenticated_user, addr
                )

                response_bytes = json.dumps(response).encode("utf-8")
                encrypted_response = aes_encrypt(aes_session_key, response_bytes)
                send_msg(client_sock, encrypted_response)

        except Exception as e:
            self.log(f"[!] Exception with {addr[1]}: {e}")
        finally:
            client_sock.close()
            with self.lock:
                self.active_clients -= 1
            self.log(f"[-] Client {addr[1]} disconnected.")

    def _process_request(self, req: dict, current_user: str, addr) -> tuple[dict, str]:
        action = req.get("action")

        if action == "REGISTER":
            username = req.get("username", "").strip()
            password = req.get("password", "")
            if not username or not password:
                return {"status": "ERROR", "message": "Username and password required."}, current_user

            with self.lock:
                if username in self.db["users"]:
                    return {"status": "ERROR", "message": "Username already exists."}, current_user

                salt_hex, hash_hex = hash_master_password(password)
                self.db["users"][username] = {
                    "salt": salt_hex,
                    "password_hash": hash_hex,
                    "vault": [],
                }
                self._save_db()

            self.log(f"[{addr[1]}] Registered new user '{username}' (PBKDF2-SHA256).")
            return {"status": "OK", "message": "Registration successful! Logged in.", "vault": []}, username

        elif action == "LOGIN":
            username = req.get("username", "").strip()
            password = req.get("password", "")
            with self.lock:
                user_rec = self.db["users"].get(username)
                if not user_rec:
                    return {"status": "ERROR", "message": "Invalid username or password."}, current_user

                salt_bytes = bytes.fromhex(user_rec["salt"])
                _, computed_hash = hash_master_password(password, salt_bytes)
                if computed_hash != user_rec["password_hash"]:
                    self.log(f"[{addr[1]}] Failed login attempt for '{username}'.")
                    return {"status": "ERROR", "message": "Invalid username or password."}, current_user

                vault_items = self._decrypt_user_vault(user_rec["vault"])
            self.log(f"[{addr[1]}] User '{username}' authenticated successfully.")
            return {"status": "OK", "message": "Login successful!", "vault": vault_items}, username

        # Require authentication for vault operations
        if not current_user:
            return {"status": "ERROR", "message": "Unauthorized. Please log in."}, None

        if action == "ADD_CREDENTIAL":
            site = req.get("site", "").strip()
            account_user = req.get("account_user", "").strip()
            secret_pass = req.get("secret_pass", "")
            notes = req.get("notes", "").strip()

            if not site or not secret_pass:
                return {"status": "ERROR", "message": "Site name and password are required."}, current_user

            # Encrypt secret password at rest on the server using AES-256
            enc_pass_hex = aes_encrypt(
                self.storage_aes_key, secret_pass.encode("utf-8")
            ).hex()

            with self.lock:
                vault = self.db["users"][current_user]["vault"]
                entry_id = int(datetime.now().timestamp() * 1000)
                vault.append({
                    "id": entry_id,
                    "site": site,
                    "account_user": account_user,
                    "enc_pass": enc_pass_hex,
                    "notes": notes,
                })
                self._save_db()
                updated_vault = self._decrypt_user_vault(vault)

            self.log(f"[{addr[1]}] Stored AES-encrypted credential for '{site}' (User: {current_user}).")
            return {"status": "OK", "vault": updated_vault}, current_user

        elif action == "DELETE_CREDENTIAL":
            entry_id = req.get("id")
            with self.lock:
                vault = self.db["users"][current_user]["vault"]
                self.db["users"][current_user]["vault"] = [
                    item for item in vault if item["id"] != entry_id
                ]
                self._save_db()
                updated_vault = self._decrypt_user_vault(self.db["users"][current_user]["vault"])

            self.log(f"[{addr[1]}] Deleted credential ID {entry_id} (User: {current_user}).")
            return {"status": "OK", "vault": updated_vault}, current_user

        return {"status": "ERROR", "message": "Unknown command."}, current_user

    def _decrypt_user_vault(self, encrypted_vault: list) -> list:
        decrypted_list = []
        for item in encrypted_vault:
            plain_pass = aes_decrypt(
                self.storage_aes_key, bytes.fromhex(item["enc_pass"])
            ).decode("utf-8")
            decrypted_list.append({
                "id": item["id"],
                "site": item["site"],
                "account_user": item["account_user"],
                "secret_pass": plain_pass,
                "notes": item.get("notes", ""),
            })
        return decrypted_list


if __name__ == "__main__":
    root = tk.Tk()
    app = CyberVaultServerGUI(root)
    root.mainloop()
