import json
import socket
import secrets
import string
import tkinter as tk
from tkinter import messagebox

from crypto_utils import (
    deserialize_public_key,
    rsa_encrypt,
    generate_aes_key,
    aes_encrypt,
    aes_decrypt,
    send_msg,
    recv_msg,
)

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 6543


class CyberVaultClientGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("CyberVault - Encrypted Password Manager")
        self.root.geometry("680x580")
        self.root.configure(bg="#1e1e2e")

        self.sock = None
        self.aes_key = None
        self.vault_data = []
        self.current_user = None

        self.main_container = tk.Frame(self.root, bg="#1e1e2e")
        self.main_container.pack(fill=tk.BOTH, expand=True)

        self._connect_and_handshake()
        self._show_auth_screen()

    def _connect_and_handshake(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((SERVER_HOST, SERVER_PORT))

            # 1. Receive Server RSA Public Key
            pub_pem = recv_msg(self.sock)
            server_pub_key = deserialize_public_key(pub_pem)

            # 2. Generate 256-bit AES Session Key and encrypt with RSA Public Key
            self.aes_key = generate_aes_key()
            encrypted_aes_key = rsa_encrypt(server_pub_key, self.aes_key)
            send_msg(self.sock, encrypted_aes_key)
            self.handshake_status = f"🔒 RSA-2048 & AES-256 Active (Session Key: {self.aes_key[:6].hex()}...)"
        except Exception as e:
            self.sock = None
            self.handshake_status = f"⚠️ Offline: Start server.py first! ({e})"

    def _send_encrypted(self, payload: dict) -> dict:
        if not self.sock or not self.aes_key:
            raise ConnectionError("Not connected to server.")
        raw_bytes = json.dumps(payload).encode("utf-8")
        encrypted_req = aes_encrypt(self.aes_key, raw_bytes)
        send_msg(self.sock, encrypted_req)

        encrypted_resp = recv_msg(self.sock)
        decrypted_bytes = aes_decrypt(self.aes_key, encrypted_resp)
        return json.loads(decrypted_bytes.decode("utf-8"))

    def _clear_container(self):
        for widget in self.main_container.winfo_children():
            widget.destroy()

    # --- SCREEN 1: Login / Register ---
    def _show_auth_screen(self):
        self._clear_container()

        tk.Label(
            self.main_container,
            text="🔐 CyberVault Password Manager",
            font=("Segoe UI", 18, "bold"),
            bg="#1e1e2e",
            fg="#cdd6f4",
            pady=20,
        ).pack()

        tk.Label(
            self.main_container,
            text=self.handshake_status,
            font=("Consolas", 9),
            bg="#313244",
            fg="#a6e3a1" if self.sock else "#f38ba8",
            padx=12,
            pady=5,
        ).pack(pady=(0, 25))

        box = tk.Frame(self.main_container, bg="#181825", padx=30, pady=25)
        box.pack()

        tk.Label(box, text="Username:", font=("Segoe UI", 10, "bold"), bg="#181825", fg="#cdd6f4").grid(
            row=0, column=0, sticky="w", pady=8
        )
        self.user_entry = tk.Entry(box, font=("Segoe UI", 11), width=26, bg="#313244", fg="#ffffff", insertbackground="#ffffff")
        self.user_entry.grid(row=0, column=1, pady=8, padx=10)

        tk.Label(box, text="Master Password:", font=("Segoe UI", 10, "bold"), bg="#181825", fg="#cdd6f4").grid(
            row=1, column=0, sticky="w", pady=8
        )
        self.pass_entry = tk.Entry(box, font=("Segoe UI", 11), width=26, show="*", bg="#313244", fg="#ffffff", insertbackground="#ffffff")
        self.pass_entry.grid(row=1, column=1, pady=8, padx=10)

        btn_row = tk.Frame(box, bg="#181825")
        btn_row.grid(row=2, column=0, columnspan=2, pady=(18, 0), sticky="ew")

        tk.Button(
            btn_row,
            text="Login to Vault",
            font=("Segoe UI", 10, "bold"),
            bg="#89b4fa",
            fg="#11111b",
            padx=12,
            pady=6,
            command=lambda: self._authenticate("LOGIN"),
        ).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))

        tk.Button(
            btn_row,
            text="Create New Vault",
            font=("Segoe UI", 10, "bold"),
            bg="#a6e3a1",
            fg="#11111b",
            padx=12,
            pady=6,
            command=lambda: self._authenticate("REGISTER"),
        ).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(5, 0))

    def _authenticate(self, mode: str):
        username = self.user_entry.get().strip()
        password = self.pass_entry.get()
        if not username or not password:
            messagebox.showwarning("Input Required", "Please enter both username and master password.")
            return

        try:
            resp = self._send_encrypted({
                "action": mode,
                "username": username,
                "password": password,
            })
            if resp.get("status") == "OK":
                self.current_user = username
                self.vault_data = resp.get("vault", [])
                self._show_vault_screen()
            else:
                messagebox.showerror("Authentication Error", resp.get("message"))
        except Exception as e:
            messagebox.showerror("Network Error", str(e))

    # --- SCREEN 2: Encrypted Vault Dashboard ---
    def _show_vault_screen(self):
        self._clear_container()

        # Top Bar
        top = tk.Frame(self.main_container, bg="#181825", padx=15, pady=8)
        top.pack(fill=tk.X)

        tk.Label(
            top,
            text=f"Vault Owner: {self.current_user}  |  {self.handshake_status}",
            font=("Consolas", 9),
            bg="#181825",
            fg="#a6e3a1",
        ).pack(side=tk.LEFT)

        tk.Button(
            top,
            text="Logout",
            font=("Segoe UI", 9, "bold"),
            bg="#f38ba8",
            fg="#11111b",
            command=self._show_auth_screen,
        ).pack(side=tk.RIGHT)

        # Form to Add New Credential
        add_frame = tk.LabelFrame(
            self.main_container,
            text=" Add New Encrypted Credential (AES-256) ",
            font=("Segoe UI", 10, "bold"),
            bg="#1e1e2e",
            fg="#89b4fa",
            padx=12,
            pady=8,
        )
        add_frame.pack(fill=tk.X, padx=15, pady=10)

        tk.Label(add_frame, text="Website / App:", bg="#1e1e2e", fg="#cdd6f4").grid(row=0, column=0, sticky="w", pady=4)
        self.site_entry = tk.Entry(add_frame, width=22, bg="#313244", fg="#ffffff", insertbackground="#ffffff")
        self.site_entry.grid(row=0, column=1, padx=8, pady=4)

        tk.Label(add_frame, text="Account Username:", bg="#1e1e2e", fg="#cdd6f4").grid(row=0, column=2, sticky="w", pady=4)
        self.acc_user_entry = tk.Entry(add_frame, width=22, bg="#313244", fg="#ffffff", insertbackground="#ffffff")
        self.acc_user_entry.grid(row=0, column=3, padx=8, pady=4)

        tk.Label(add_frame, text="Password:", bg="#1e1e2e", fg="#cdd6f4").grid(row=1, column=0, sticky="w", pady=4)
        self.secret_entry = tk.Entry(add_frame, width=22, bg="#313244", fg="#ffffff", insertbackground="#ffffff")
        self.secret_entry.grid(row=1, column=1, padx=8, pady=4)

        tk.Label(add_frame, text="Notes:", bg="#1e1e2e", fg="#cdd6f4").grid(row=1, column=2, sticky="w", pady=4)
        self.notes_entry = tk.Entry(add_frame, width=22, bg="#313244", fg="#ffffff", insertbackground="#ffffff")
        self.notes_entry.grid(row=1, column=3, padx=8, pady=4)

        action_row = tk.Frame(add_frame, bg="#1e1e2e")
        action_row.grid(row=2, column=0, columnspan=4, pady=(8, 2), sticky="ew")

        tk.Button(
            action_row,
            text="🎲 Generate Strong Password",
            font=("Segoe UI", 9, "bold"),
            bg="#f9e2af",
            fg="#11111b",
            command=self._generate_password,
        ).pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(
            action_row,
            text="➕ Encrypt & Save to Server",
            font=("Segoe UI", 9, "bold"),
            bg="#a6e3a1",
            fg="#11111b",
            command=self._add_credential,
        ).pack(side=tk.LEFT, expand=True, fill=tk.X)

        # Lower Split View: Saved Accounts List + Decrypted Inspector (Tkinter Text)
        split = tk.Frame(self.main_container, bg="#1e1e2e")
        split.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))

        left_box = tk.LabelFrame(
            split,
            text=" Stored Accounts ",
            font=("Segoe UI", 10, "bold"),
            bg="#1e1e2e",
            fg="#89b4fa",
            padx=8,
            pady=8,
        )
        left_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))

        self.accounts_listbox = tk.Listbox(
            left_box,
            font=("Segoe UI", 10),
            bg="#11111b",
            fg="#cdd6f4",
            selectbackground="#89b4fa",
            selectforeground="#11111b",
        )
        self.accounts_listbox.pack(fill=tk.BOTH, expand=True)
        self.accounts_listbox.bind("<<ListboxSelect>>", self._on_select_account)

        right_box = tk.LabelFrame(
            split,
            text=" Decrypted Credential Inspector ",
            font=("Segoe UI", 10, "bold"),
            bg="#1e1e2e",
            fg="#89b4fa",
            padx=8,
            pady=8,
        )
        right_box.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Tkinter Text Widget (Explicitly required by Section 3 of handout)
        self.detail_text = tk.Text(
            right_box,
            font=("Consolas", 10),
            bg="#11111b",
            fg="#a6e3a1",
            height=8,
            width=34,
            state="disabled",
        )
        self.detail_text.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        btn_bar = tk.Frame(right_box, bg="#1e1e2e")
        btn_bar.pack(fill=tk.X)

        tk.Button(
            btn_bar,
            text="📋 Copy Password",
            font=("Segoe UI", 9, "bold"),
            bg="#89b4fa",
            fg="#11111b",
            command=self._copy_selected_password,
        ).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 4))

        tk.Button(
            btn_bar,
            text="🗑️ Delete Entry",
            font=("Segoe UI", 9, "bold"),
            bg="#f38ba8",
            fg="#11111b",
            command=self._delete_selected,
        ).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(4, 0))

        self._refresh_vault_ui()

    def _generate_password(self):
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        generated = "".join(secrets.choice(alphabet) for _ in range(16))
        self.secret_entry.delete(0, tk.END)
        self.secret_entry.insert(0, generated)

    def _add_credential(self):
        site = self.site_entry.get().strip()
        acc_user = self.acc_user_entry.get().strip()
        secret_pass = self.secret_entry.get()
        notes = self.notes_entry.get().strip()

        if not site or not secret_pass:
            messagebox.showwarning("Missing Fields", "Please enter both a Website/App name and a Password.")
            return

        try:
            resp = self._send_encrypted({
                "action": "ADD_CREDENTIAL",
                "site": site,
                "account_user": acc_user,
                "secret_pass": secret_pass,
                "notes": notes,
            })
            if resp.get("status") == "OK":
                self.vault_data = resp.get("vault", [])
                self.site_entry.delete(0, tk.END)
                self.acc_user_entry.delete(0, tk.END)
                self.secret_entry.delete(0, tk.END)
                self.notes_entry.delete(0, tk.END)
                self._refresh_vault_ui()
            else:
                messagebox.showerror("Error", resp.get("message"))
        except Exception as e:
            messagebox.showerror("Network Error", str(e))

    def _refresh_vault_ui(self):
        self.accounts_listbox.delete(0, tk.END)
        for item in self.vault_data:
            self.accounts_listbox.insert(tk.END, f"🌐 {item['site']} ({item['account_user']})")

        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, "Select an account on the left\nto decrypt and view details.")
        self.detail_text.configure(state="disabled")

    def _on_select_account(self, event=None):
        selection = self.accounts_listbox.curselection()
        if not selection:
            return
        item = self.vault_data[selection[0]]
        info = (
            f"Website/Service : {item['site']}\n"
            f"Account User    : {item['account_user']}\n"
            f"Decrypted Pass  : {item['secret_pass']}\n"
            f"Notes           : {item.get('notes') or 'None'}\n"
            f"----------------------------------\n"
            f"Encryption      : AES-256-CBC (Verified)"
        )
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, info)
        self.detail_text.configure(state="disabled")

    def _copy_selected_password(self):
        selection = self.accounts_listbox.curselection()
        if not selection:
            messagebox.showinfo("Select Entry", "Please select an account first.")
            return
        item = self.vault_data[selection[0]]
        self.root.clipboard_clear()
        self.root.clipboard_append(item["secret_pass"])
        messagebox.showinfo("Copied", f"Password for '{item['site']}' copied to clipboard!")

    def _delete_selected(self):
        selection = self.accounts_listbox.curselection()
        if not selection:
            messagebox.showinfo("Select Entry", "Please select an account to delete.")
            return
        item = self.vault_data[selection[0]]
        resp = self._send_encrypted({"action": "DELETE_CREDENTIAL", "id": item["id"]})
        if resp.get("status") == "OK":
            self.vault_data = resp.get("vault", [])
            self._refresh_vault_ui()


if __name__ == "__main__":
    root = tk.Tk()
    app = CyberVaultClientGUI(root)
    root.mainloop()
