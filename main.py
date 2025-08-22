# simple_multi_cipher_tool.py
import os
import base64
import hashlib
import secrets
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import pyperclip

# -----------------------
# Config
# -----------------------
FIXED_SALT = "ProfessionalEncryptionTool_v1.0"

# -----------------------
# Helper: Gate -> Fernet Key
# -----------------------
def generate_key_from_gate(gate_name: str) -> bytes:
    if not gate_name or gate_name == "Select Gate":
        raise ValueError("Gate name required")
    combined = (gate_name + "|" + FIXED_SALT).encode()
    digest = hashlib.sha256(combined).digest()
    return base64.urlsafe_b64encode(digest)  # valid Fernet key (32 bytes -> base64)

# -----------------------
# Caesar Cipher
# -----------------------
def caesar_shift_char(ch: str, shift: int) -> str:
    if ch.isalpha():
        base = ord('A') if ch.isupper() else ord('a')
        return chr((ord(ch) - base + shift) % 26 + base)
    return ch

def caesar_encrypt(text: str, shift: int = 3) -> str:
    return ''.join(caesar_shift_char(c, shift) for c in text)

def caesar_decrypt(text: str, shift: int = 3) -> str:
    return caesar_encrypt(text, -shift)

# -----------------------
# Substitution Cipher (fixed mapping)
# -----------------------
SUB_MAP = {
    "A":"Q","B":"W","C":"E","D":"R","E":"T","F":"Y","G":"U","H":"I","I":"O","J":"P",
    "K":"A","L":"S","M":"D","N":"F","O":"G","P":"H","Q":"J","R":"K","S":"L","T":"Z",
    "U":"X","V":"C","W":"V","X":"B","Y":"N","Z":"M"
}
REV_SUB_MAP = {v: k for k, v in SUB_MAP.items()}

def substitute_char(ch: str, mapping: dict) -> str:
    if not ch.isalpha():
        return ch
    is_upper = ch.isupper()
    mapped = mapping.get(ch.upper(), ch.upper())
    return mapped if is_upper else mapped.lower()

def substitution_encrypt(text: str) -> str:
    return ''.join(substitute_char(c, SUB_MAP) for c in text)

def substitution_decrypt(text: str) -> str:
    return ''.join(substitute_char(c, REV_SUB_MAP) for c in text)

# -----------------------
# Hill Cipher (2x2) - simple educational implementation
# key format: "a,b,c,d" (row-major)
# -----------------------
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, _ = egcd(a % m, m)
    if g != 1:
        return None
    return x % m

def parse_hill_key(raw: str):
    parts = [p.strip() for p in raw.split(",") if p.strip() != ""]
    if len(parts) != 4:
        raise ValueError("Hill key must be 4 integers separated by commas (a,b,c,d).")
    mat = [int(x) % 26 for x in parts]
    return [[mat[0], mat[1]], [mat[2], mat[3]]]

def hill_encrypt(plain: str, key_matrix):
    p = ''.join([c.upper() for c in plain if c.isalpha()])
    if len(p) % 2 == 1:
        p += 'X'
    out = []
    for i in range(0, len(p), 2):
        v1 = ord(p[i]) - 65
        v2 = ord(p[i+1]) - 65
        c1 = (key_matrix[0][0]*v1 + key_matrix[0][1]*v2) % 26
        c2 = (key_matrix[1][0]*v1 + key_matrix[1][1]*v2) % 26
        out.append(chr(c1 + 65))
        out.append(chr(c2 + 65))
    return ''.join(out)

def hill_decrypt(cipher: str, key_matrix):
    c = ''.join([ch.upper() for ch in cipher if ch.isalpha()])
    a, b = key_matrix[0]
    c2, d = key_matrix[1]
    det = (a*d - b*c2) % 26
    inv_det = modinv(det, 26)
    if inv_det is None:
        raise ValueError("Hill key matrix not invertible modulo 26.")
    inv = [
        [(d * inv_det) % 26, ((-b) * inv_det) % 26],
        (((-c2) * inv_det) % 26, (a * inv_det) % 26)
    ]
    out = []
    for i in range(0, len(c), 2):
        v1 = ord(c[i]) - 65
        v2 = ord(c[i+1]) - 65
        p1 = (inv[0][0]*v1 + inv[0][1]*v2) % 26
        p2 = (inv[1][0]*v1 + inv[1][1]*v2) % 26
        out.append(chr(p1 + 65))
        out.append(chr(p2 + 65))
    return ''.join(out)

# -----------------------
# Playfair Cipher (I/J merged)
# -----------------------
def build_playfair_square(key_phrase: str):
    key_phrase = key_phrase.upper().replace("J", "I")
    seen = []
    for ch in key_phrase:
        if ch.isalpha() and ch not in seen:
            seen.append(ch)
    for ch in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
        if ch not in seen:
            seen.append(ch)
    grid = [seen[i*5:(i+1)*5] for i in range(5)]
    pos = {grid[r][c]: (r, c) for r in range(5) for c in range(5)}
    return grid, pos

def playfair_prepare(text: str):
    txt = ''.join([c.upper().replace("J","I") for c in text if c.isalpha()])
    pairs = []
    i = 0
    while i < len(txt):
        a = txt[i]
        b = txt[i+1] if i+1 < len(txt) else 'X'
        if a == b:
            pairs.append(a + 'X')
            i += 1
        else:
            pairs.append(a + b)
            i += 2
    if len(pairs[-1]) == 1:
        pairs[-1] += 'X'
    return pairs

def playfair_encrypt(plain: str, key_phrase: str):
    grid, pos = build_playfair_square(key_phrase)
    pairs = playfair_prepare(plain)
    out = []
    for pair in pairs:
        r1, c1 = pos[pair[0]]
        r2, c2 = pos[pair[1]]
        if r1 == r2:
            out.append(grid[r1][(c1+1)%5])
            out.append(grid[r2][(c2+1)%5])
        elif c1 == c2:
            out.append(grid[(r1+1)%5][c1])
            out.append(grid[(r2+1)%5][c2])
        else:
            out.append(grid[r1][c2])
            out.append(grid[r2][c1])
    return ''.join(out)

def playfair_decrypt(cipher: str, key_phrase: str):
    grid, pos = build_playfair_square(key_phrase)
    txt = ''.join([c.upper() for c in cipher if c.isalpha()])
    pairs = [txt[i:i+2] for i in range(0, len(txt), 2)]
    out = []
    for pair in pairs:
        r1, c1 = pos[pair[0]]
        r2, c2 = pos[pair[1]]
        if r1 == r2:
            out.append(grid[r1][(c1-1)%5])
            out.append(grid[r2][(c2-1)%5])
        elif c1 == c2:
            out.append(grid[(r1-1)%5][c1])
            out.append(grid[(r2-1)%5][c2])
        else:
            out.append(grid[r1][c2])
            out.append(grid[r2][c1])
    return ''.join(out)

# -----------------------
# PGP-like RSA-4096 Hybrid (AES-GCM + RSA-OAEP)
# -----------------------
def generate_rsa_4096_keypair(priv_path: str, pub_path: str):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(priv_path, 'wb') as f:
        f.write(priv_pem)
    with open(pub_path, 'wb') as f:
        f.write(pub_pem)
    return priv_path, pub_path

def load_public_key(path: str):
    with open(path, 'rb') as f:
        data = f.read()
    return serialization.load_pem_public_key(data)

def load_private_key(path: str):
    with open(path, 'rb') as f:
        data = f.read()
    return serialization.load_pem_private_key(data, password=None)

def pgp_encrypt_bytes(public_key, data: bytes) -> bytes:
    aes_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(aes_key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, data, None)
    enc_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    # Package as base64 parts joined by :: (safe for text)
    payload = base64.b64encode(enc_key) + b"::" + base64.b64encode(nonce) + b"::" + base64.b64encode(ct)
    return payload

def pgp_decrypt_bytes(private_key, payload: bytes) -> bytes:
    parts = payload.split(b"::")
    if len(parts) != 3:
        raise ValueError("Invalid PGP payload format.")
    enc_key = base64.b64decode(parts[0])
    nonce = base64.b64decode(parts[1])
    ct = base64.b64decode(parts[2])
    aes_key = private_key.decrypt(
        enc_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    aesgcm = AESGCM(aes_key)
    data = aesgcm.decrypt(nonce, ct, None)
    return data

# -----------------------
# GUI and callbacks
# -----------------------
current_public_key = None
current_private_key = None

root = tk.Tk()
root.title("Simple Multi-Cipher Tool")
root.geometry("900x680")
root.configure(bg="#121212")
root.resizable(False, False)

# Top controls
top = tk.Frame(root, bg="#121212")
top.pack(fill=tk.X, padx=12, pady=8)

cipher_var = tk.StringVar(value="Fernet (Gate Key)")
cipher_choices = [
    "Fernet (Gate Key)",
    "Caesar Cipher",
    "Substitution Cipher",
    "Hill Cipher (2x2)",
    "Playfair Cipher",
    "PGP (RSA-4096)"
]

tk.Label(top, text="Cipher:", fg="#DDDDDD", bg="#121212").pack(side=tk.LEFT, padx=(6,2))
cipher_cb = ttk.Combobox(top, values=cipher_choices, textvariable=cipher_var, state="readonly", width=24)
cipher_cb.pack(side=tk.LEFT, padx=(0,8))

# Gate
tk.Label(top, text="Gate:", fg="#DDDDDD", bg="#121212").pack(side=tk.LEFT, padx=(6,2))
gate_var = tk.StringVar(value="AND")
gate_cb = ttk.Combobox(top, values=["AND","OR","XOR","NAND","NOR"], textvariable=gate_var, state="readonly", width=10)
gate_cb.pack(side=tk.LEFT, padx=(0,8))

# Caesar shift
tk.Label(top, text="Shift:", fg="#DDDDDD", bg="#121212").pack(side=tk.LEFT, padx=(6,2))
shift_entry = tk.Entry(top, width=6)
shift_entry.insert(0, "3")
shift_entry.pack(side=tk.LEFT, padx=(0,8))

# Hill key
tk.Label(top, text="Hill key a,b,c,d:", fg="#DDDDDD", bg="#121212").pack(side=tk.LEFT, padx=(6,2))
hill_key_entry = tk.Entry(top, width=12)
hill_key_entry.insert(0, "3,3,2,5")
hill_key_entry.pack(side=tk.LEFT, padx=(0,8))

# Playfair key
tk.Label(top, text="Playfair key:", fg="#DDDDDD", bg="#121212").pack(side=tk.LEFT, padx=(6,2))
playfair_key_entry = tk.Entry(top, width=12)
playfair_key_entry.insert(0, "MONARCHY")
playfair_key_entry.pack(side=tk.LEFT, padx=(0,8))

# PGP buttons
pgp_frame = tk.Frame(root, bg="#121212")
pgp_frame.pack(fill=tk.X, padx=12, pady=(0,6))
tk.Button(pgp_frame, text="Generate RSA-4096", command=lambda: generate_keys(), bg="#333", fg="white").pack(side=tk.LEFT, padx=6)
tk.Button(pgp_frame, text="Load Public Key", command=lambda: load_pub(), bg="#333", fg="white").pack(side=tk.LEFT, padx=6)
tk.Button(pgp_frame, text="Load Private Key", command=lambda: load_priv(), bg="#333", fg="white").pack(side=tk.LEFT, padx=6)

# Text area
text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=110, height=28, bg="#1E1E1E", fg="#EDEDED", insertbackground="white", font=("Consolas", 11))
text_area.pack(padx=12, pady=(4,8), fill=tk.BOTH, expand=True)

# Buttons
btn_frame = tk.Frame(root, bg="#121212")
btn_frame.pack(fill=tk.X, padx=12, pady=(0,10))

def get_shift():
    try:
        s = int(shift_entry.get().strip())
        return s % 26
    except Exception:
        return 3

def generate_keys():
    priv_path = filedialog.asksaveasfilename(title="Save private key as", defaultextension=".pem", filetypes=[("PEM","*.pem")])
    if not priv_path:
        return
    pub_path = filedialog.asksaveasfilename(title="Save public key as", defaultextension=".pem", filetypes=[("PEM","*.pem")])
    if not pub_path:
        return
    try:
        generate_rsa_4096_keypair(priv_path, pub_path)
        messagebox.showinfo("Keys", "RSA-4096 keypair generated and saved.")
    except Exception as e:
        messagebox.showerror("Keygen error", str(e))

def load_pub():
    global current_public_key
    path = filedialog.askopenfilename(title="Select public key (PEM)", filetypes=[("PEM","*.pem"), ("All","*.*")])
    if not path:
        return
    try:
        current_public_key = load_public_key(path)
        messagebox.showinfo("Public Key", "Public key loaded.")
    except Exception as e:
        messagebox.showerror("Load public key", str(e))

def load_priv():
    global current_private_key
    path = filedialog.askopenfilename(title="Select private key (PEM)", filetypes=[("PEM","*.pem"), ("All","*.*")])
    if not path:
        return
    try:
        current_private_key = load_private_key(path)
        messagebox.showinfo("Private Key", "Private key loaded.")
    except Exception as e:
        messagebox.showerror("Load private key", str(e))

def encrypt_text():
    mode = cipher_var.get()
    plain = text_area.get("1.0", tk.END).strip()
    if not plain:
        messagebox.showwarning("Empty", "Please enter text to encrypt.")
        return
    try:
        if mode == "Fernet (Gate Key)":
            key = generate_key_from_gate(gate_var.get())
            f = Fernet(key)
            out = f.encrypt(plain.encode()).decode()
        elif mode == "Caesar Cipher":
            out = caesar_encrypt(plain, get_shift())
        elif mode == "Substitution Cipher":
            out = substitution_encrypt(plain)
        elif mode == "Hill Cipher (2x2)":
            km = parse_hill_key(hill_key_entry.get().strip())
            out = hill_encrypt(plain, km)
        elif mode == "Playfair Cipher":
            out = playfair_encrypt(plain, playfair_key_entry.get().strip() or "KEY")
        elif mode == "PGP (RSA-4096)":
            if current_public_key is None:
                messagebox.showwarning("PGP", "Load a public key first.")
                return
            payload = pgp_encrypt_bytes(current_public_key, plain.encode())
            out = payload.decode()
        else:
            out = plain
        text_area.delete("1.0", tk.END)
        text_area.insert(tk.END, out)
    except Exception as e:
        messagebox.showerror("Encryption error", str(e))

def decrypt_text():
    mode = cipher_var.get()
    blob = text_area.get("1.0", tk.END).strip()
    if not blob:
        messagebox.showwarning("Empty", "Please enter text to decrypt.")
        return
    try:
        if mode == "Fernet (Gate Key)":
            key = generate_key_from_gate(gate_var.get())
            f = Fernet(key)
            dec_bytes = f.decrypt(blob.encode())
            out = dec_bytes.decode()
        elif mode == "Caesar Cipher":
            out = caesar_decrypt(blob, get_shift())
        elif mode == "Substitution Cipher":
            out = substitution_decrypt(blob)
        elif mode == "Hill Cipher (2x2)":
            km = parse_hill_key(hill_key_entry.get().strip())
            out = hill_decrypt(blob, km)
        elif mode == "Playfair Cipher":
            out = playfair_decrypt(blob, playfair_key_entry.get().strip() or "KEY")
        elif mode == "PGP (RSA-4096)":
            if current_private_key is None:
                messagebox.showwarning("PGP", "Load a private key first.")
                return
            data = pgp_decrypt_bytes(current_private_key, blob.encode())
            out = data.decode()
        else:
            out = blob
        text_area.delete("1.0", tk.END)
        text_area.insert(tk.END, out)
    except Exception as e:
        messagebox.showerror("Decryption error", str(e))

def encrypt_file():
    mode = cipher_var.get()
    if mode not in ("Fernet (Gate Key)", "PGP (RSA-4096)"):
        messagebox.showinfo("Files", "File encryption is only for Fernet and PGP modes.")
        return
    file_path = filedialog.askopenfilename(title="Select file to encrypt")
    if not file_path:
        return
    try:
        with open(file_path, "rb") as fr:
            data = fr.read()
        if mode == "Fernet (Gate Key)":
            key = generate_key_from_gate(gate_var.get())
            f = Fernet(key)
            enc = f.encrypt(data)
        else:  # PGP
            if current_public_key is None:
                messagebox.showwarning("PGP", "Load a public key first.")
                return
            enc = pgp_encrypt_bytes(current_public_key, data)
        save_path = filedialog.asksaveasfilename(title="Save encrypted file as", initialfile=os.path.basename(file_path) + ".encrypted")
        if save_path:
            with open(save_path, "wb") as fw:
                fw.write(enc)
            messagebox.showinfo("Success", f"Encrypted and saved to: {save_path}")
    except Exception as e:
        messagebox.showerror("File encrypt error", str(e))

def decrypt_file():
    mode = cipher_var.get()
    if mode not in ("Fernet (Gate Key)", "PGP (RSA-4096)"):
        messagebox.showinfo("Files", "File decryption is only for Fernet and PGP modes.")
        return
    file_path = filedialog.askopenfilename(title="Select encrypted file", filetypes=[("Encrypted","*.encrypted"), ("All","*.*")])
    if not file_path:
        return
    try:
        with open(file_path, "rb") as fr:
            data = fr.read()
        if mode == "Fernet (Gate Key)":
            key = generate_key_from_gate(gate_var.get())
            f = Fernet(key)
            dec = f.decrypt(data)
        else:
            if current_private_key is None:
                messagebox.showwarning("PGP", "Load a private key first.")
                return
            dec = pgp_decrypt_bytes(current_private_key, data)
        save_path = filedialog.asksaveasfilename(title="Save decrypted file as", initialfile=os.path.basename(file_path).replace(".encrypted", ".decrypted"))
        if save_path:
            with open(save_path, "wb") as fw:
                fw.write(dec)
            messagebox.showinfo("Success", f"Decrypted and saved to: {save_path}")
    except Exception as e:
        messagebox.showerror("File decrypt error", str(e))

def copy_clip():
    txt = text_area.get("1.0", tk.END).strip()
    if not txt:
        messagebox.showwarning("Empty", "Nothing to copy.")
        return
    pyperclip.copy(txt)
    messagebox.showinfo("Copied", "Text copied to clipboard.")

def paste_clip():
    try:
        txt = pyperclip.paste()
        text_area.delete("1.0", tk.END)
        text_area.insert(tk.END, txt)
    except Exception as e:
        messagebox.showerror("Clipboard error", str(e))

tk.Button(btn_frame, text="Encrypt Text", command=encrypt_text, bg="#1565C0", fg="white").pack(side=tk.LEFT, padx=6)
tk.Button(btn_frame, text="Decrypt Text", command=decrypt_text, bg="#2E7D32", fg="white").pack(side=tk.LEFT, padx=6)
tk.Button(btn_frame, text="Encrypt File", command=encrypt_file, bg="#8E24AA", fg="white").pack(side=tk.LEFT, padx=6)
tk.Button(btn_frame, text="Decrypt File", command=decrypt_file, bg="#C62828", fg="white").pack(side=tk.LEFT, padx=6)
tk.Button(btn_frame, text="Copy", command=copy_clip, bg="#FFC107").pack(side=tk.LEFT, padx=6)
tk.Button(btn_frame, text="Paste", command=paste_clip, bg="#FF7043").pack(side=tk.LEFT, padx=6)

# Run
root.mainloop()
