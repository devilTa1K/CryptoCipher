import os
import base64
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from cryptography.fernet import Fernet
import pyperclip

# ============================
# Config / Constants
# ============================
APP_TITLE = "🔐 Multi-Cipher Encryption Tool"
FIXED_SALT = "ProfessionalEncryptionTool_v1.0"

# ============================
# Key derivation from Gate (for Fernet)
# ============================
def generate_key_from_gate(gate_name: str) -> bytes:
    """Derive a 32-byte value from (gate_name + FIXED_SALT) via SHA-256,
    then return it base64-urlsafe-encoded for Fernet.
    """
    if not gate_name or gate_name == "Select Gate":
        raise ValueError("Gate name required")
    combined = (gate_name + "|" + FIXED_SALT).encode()
    digest = hashlib.sha256(combined).digest()  # 32 bytes
    return base64.urlsafe_b64encode(digest)     # valid Fernet key

# ============================
# Caesar Cipher
# ============================
def caesar_shift_char(ch: str, shift: int) -> str:
    if ch.isalpha():
        base = ord('A') if ch.isupper() else ord('a')
        return chr((ord(ch) - base + shift) % 26 + base)
    return ch

def caesar_encrypt(text: str, shift: int = 3) -> str:
    return ''.join(caesar_shift_char(c, shift) for c in text)

def caesar_decrypt(text: str, shift: int = 3) -> str:
    return caesar_encrypt(text, -shift)

# ============================
# Substitution Cipher (fixed mapping)
# Mapping chosen for demo; you can customize.
# ============================
SUB_MAP_UPPER = {
    "A":"Q","B":"W","C":"E","D":"R","E":"T","F":"Y","G":"U","H":"I","I":"O","J":"P",
    "K":"A","L":"S","M":"D","N":"F","O":"G","P":"H","Q":"J","R":"K","S":"L","T":"Z",
    "U":"X","V":"C","W":"V","X":"B","Y":"N","Z":"M"
}
REV_SUB_MAP_UPPER = {v: k for k, v in SUB_MAP_UPPER.items()}

def _subst_map_char(ch: str, mapping: dict) -> str:
    if ch.isalpha():
        is_upper = ch.isupper()
        up = ch.upper()
        mapped = mapping.get(up, up)
        return mapped if is_upper else mapped.lower()
    return ch

def substitution_encrypt(text: str) -> str:
    return ''.join(_subst_map_char(c, SUB_MAP_UPPER) for c in text)

def substitution_decrypt(text: str) -> str:
    return ''.join(_subst_map_char(c, REV_SUB_MAP_UPPER) for c in text)

# ============================
# GUI Callbacks: Text Encryption / Decryption
# ============================
def get_caesar_shift_value() -> int:
    """Read shift from entry; default to 3 on invalid input."""
    raw = shift_entry.get().strip()
    if raw == "":
        return 3
    try:
        val = int(raw)
        # Normalize overly large values
        if val > 10_000 or val < -10_000:
            val = val % 26
        return val
    except ValueError:
        messagebox.showwarning("Shift value", "Invalid shift. Using default shift = 3.")
        return 3

def encrypt_text():
    cipher = cipher_var.get()
    plain = text_area.get("1.0", tk.END).rstrip("\n")
    if not plain:
        messagebox.showwarning("Input empty", "Please enter text to encrypt.")
        return

    try:
        if cipher == "Fernet (Gate Key)":
            gate = gate_var.get()
            if gate == "Select Gate":
                messagebox.showwarning("Select Gate", "Please choose a gate from the dropdown.")
                return
            key = generate_key_from_gate(gate)
            f = Fernet(key)
            encrypted = f.encrypt(plain.encode()).decode()
        elif cipher == "Caesar Cipher":
            shift = get_caesar_shift_value()
            encrypted = caesar_encrypt(plain, shift)
        elif cipher == "Substitution Cipher":
            encrypted = substitution_encrypt(plain)
        else:
            encrypted = plain

        text_area.delete("1.0", tk.END)
        text_area.insert(tk.END, encrypted)
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))


def decrypt_text():
    cipher = cipher_var.get()
    blob = text_area.get("1.0", tk.END).strip()
    if not blob:
        messagebox.showwarning("Input empty", "Please enter encrypted text to decrypt.")
        return

    try:
        if cipher == "Fernet (Gate Key)":
            gate = gate_var.get()
            if gate == "Select Gate":
                messagebox.showwarning("Select Gate", "Please choose a gate from the dropdown.")
                return
            key = generate_key_from_gate(gate)
            f = Fernet(key)
            decrypted_bytes = f.decrypt(blob.encode())
            try:
                decrypted = decrypted_bytes.decode()
            except UnicodeDecodeError:
                # If it's binary data, show info and do not overwrite
                messagebox.showinfo("Decrypted (binary)", "Decryption succeeded but result is binary data. Use 'Decrypt File' for files.")
                return
        elif cipher == "Caesar Cipher":
            shift = get_caesar_shift_value()
            decrypted = caesar_decrypt(blob, shift)
        elif cipher == "Substitution Cipher":
            decrypted = substitution_decrypt(blob)
        else:
            decrypted = blob

        text_area.delete("1.0", tk.END)
        text_area.insert(tk.END, decrypted)
    except Exception:
        messagebox.showerror("Decryption Error", "Failed to decrypt. Wrong key/shift or invalid data.")

# ============================
# File Encryption / Decryption (Fernet only)
# ============================
def encrypt_file():
    if cipher_var.get() != "Fernet (Gate Key)":
        messagebox.showinfo("Files not supported", "File encryption is only available with Fernet.")
        return

    gate = gate_var.get()
    if gate == "Select Gate":
        messagebox.showwarning("Select Gate", "Please choose a gate from the dropdown.")
        return

    file_path = filedialog.askopenfilename(title="Select file to encrypt")
    if not file_path:
        return
    try:
        key = generate_key_from_gate(gate)
        f = Fernet(key)
        with open(file_path, "rb") as fr:
            data = fr.read()
        encrypted = f.encrypt(data)
        default_name = os.path.basename(file_path) + ".encrypted"
        save_path = filedialog.asksaveasfilename(
            title="Save encrypted file as",
            initialfile=default_name,
            defaultextension=".encrypted",
            filetypes=[("Encrypted files", "*.encrypted"), ("All files", "*.*")]
        )
        if save_path:
            with open(save_path, "wb") as fw:
                fw.write(encrypted)
            messagebox.showinfo("Success", f"Encrypted and saved to:\n{save_path}")
    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))


def decrypt_file():
    if cipher_var.get() != "Fernet (Gate Key)":
        messagebox.showinfo("Files not supported", "File decryption is only available with Fernet.")
        return

    gate = gate_var.get()
    if gate == "Select Gate":
        messagebox.showwarning("Select Gate", "Please choose a gate from the dropdown.")
        return

    file_path = filedialog.askopenfilename(
        title="Select encrypted file",
        filetypes=[("Encrypted files", "*.encrypted"), ("All files", "*.*")]
    )
    if not file_path:
        return

    try:
        key = generate_key_from_gate(gate)
        f = Fernet(key)
        with open(file_path, "rb") as fr:
            encrypted_data = fr.read()
        decrypted = f.decrypt(encrypted_data)
        default_name = os.path.basename(file_path).replace(".encrypted", ".decrypted")
        save_path = filedialog.asksaveasfilename(
            title="Save decrypted file as",
            initialfile=default_name
        )
        if save_path:
            with open(save_path, "wb") as fw:
                fw.write(decrypted)
            messagebox.showinfo("Success", f"Decrypted and saved to:\n{save_path}")
    except Exception:
        messagebox.showerror("Decryption Error", "Failed to decrypt file. Wrong gate or corrupted file.")

# ============================
# Clipboard utilities
# ============================
def copy_to_clipboard():
    content = text_area.get("1.0", tk.END).strip()
    if not content:
        messagebox.showwarning("Empty", "Nothing to copy.")
        return
    pyperclip.copy(content)
    messagebox.showinfo("Copied", "Text copied to clipboard.")


def paste_from_clipboard():
    try:
        txt = pyperclip.paste()
        text_area.delete("1.0", tk.END)
        text_area.insert(tk.END, txt)
    except Exception as e:
        messagebox.showerror("Clipboard Error", str(e))

# ============================
# UI - Professional Dark Theme
# ============================
root = tk.Tk()
root.title(APP_TITLE)
root.geometry("820x600")
root.configure(bg="#121212")
root.resizable(False, False)

# ---- Top frame (title + selectors)
top_frame = tk.Frame(root, bg="#121212")
top_frame.pack(fill=tk.X, padx=16, pady=(12, 6))

title_lbl = tk.Label(
    top_frame,
    text="Multi-Cipher Encryption (Fernet + Caesar + Substitution)",
    fg="white",
    bg="#121212",
    font=("Segoe UI", 16, "bold")
)
title_lbl.pack(side=tk.LEFT)

# Right controls container
controls_frame = tk.Frame(top_frame, bg="#121212")
controls_frame.pack(side=tk.RIGHT)

# Cipher selection
cipher_var = tk.StringVar(value="Fernet (Gate Key)")
ciphers = ["Fernet (Gate Key)", "Caesar Cipher", "Substitution Cipher"]

cipher_label = tk.Label(controls_frame, text="Cipher:", fg="#DDDDDD", bg="#121212", font=("Segoe UI", 10))
cipher_label.grid(row=0, column=0, padx=(0, 6), pady=2, sticky="e")

cipher_combo = ttk.Combobox(
    controls_frame,
    values=ciphers,
    state="readonly",
    textvariable=cipher_var,
    width=22,
    font=("Segoe UI", 10)
)
cipher_combo.grid(row=0, column=1, pady=2)

# Gate selection (Fernet only)
gate_var = tk.StringVar(value="AND")
gates = ["AND", "OR", "XOR", "NAND", "NOR"]

gate_label = tk.Label(controls_frame, text="Gate:", fg="#DDDDDD", bg="#121212", font=("Segoe UI", 10))
gate_label.grid(row=1, column=0, padx=(0, 6), pady=2, sticky="e")

gate_combo = ttk.Combobox(
    controls_frame,
    values=gates,
    state="readonly",
    textvariable=gate_var,
    width=22,
    font=("Segoe UI", 10)
)
gate_combo.grid(row=1, column=1, pady=2)

# Caesar shift (Caesar only)
shift_label = tk.Label(controls_frame, text="Shift:", fg="#DDDDDD", bg="#121212", font=("Segoe UI", 10))
shift_label.grid(row=2, column=0, padx=(0, 6), pady=2, sticky="e")

shift_entry = tk.Entry(controls_frame, width=24, font=("Segoe UI", 10))
shift_entry.insert(0, "3")
shift_entry.grid(row=2, column=1, pady=2)

# Helper: enable/disable controls based on selected cipher
def update_controls(*_):
    c = cipher_var.get()
    is_fernet = (c == "Fernet (Gate Key)")
    is_caesar = (c == "Caesar Cipher")

    # Gate controls
    state_gate = "normal" if is_fernet else "disabled"
    gate_combo.configure(state="readonly" if is_fernet else "disabled")
    gate_label.configure(fg="#DDDDDD" if is_fernet else "#6A6A6A")

    # Shift controls
    state_shift = "normal" if is_caesar else "disabled"
    shift_entry.configure(state=state_shift)
    shift_label.configure(fg="#DDDDDD" if is_caesar else "#6A6A6A")

    # File buttons
    state_files = tk.NORMAL if is_fernet else tk.DISABLED
    encrypt_file_btn.configure(state=state_files)
    decrypt_file_btn.configure(state=state_files)

cipher_combo.bind("<<ComboboxSelected>>", update_controls)

# ---- Middle frame (text area)
middle_frame = tk.Frame(root, bg="#121212")
middle_frame.pack(fill=tk.BOTH, expand=True, padx=16, pady=6)

label = tk.Label(
    middle_frame,
    text="Enter text (or paste encrypted text here):",
    fg="#CCCCCC",
    bg="#121212",
    font=("Segoe UI", 11)
)
label.pack(anchor="w", pady=(4, 6))

text_area = scrolledtext.ScrolledText(
    middle_frame,
    wrap=tk.WORD,
    width=96,
    height=20,
    font=("Consolas", 11),
    bg="#1E1E1E",
    fg="#EDEDED",
    insertbackground="white",
)
text_area.pack(fill=tk.BOTH, expand=True)

# ---- Buttons frame (text actions)
btn_frame = tk.Frame(root, bg="#121212")
btn_frame.pack(fill=tk.X, padx=16, pady=(8, 4))


def styled_button(parent, text, cmd, width=16, bg="#2D2D2D"):
    btn = tk.Button(
        parent,
        text=text,
        command=cmd,
        width=width,
        font=("Segoe UI", 10, "bold"),
        bg=bg,
        fg="white",
        activebackground="#555555",
        bd=0,
        padx=6,
        pady=8,
    )
    return btn

encrypt_btn = styled_button(btn_frame, "Encrypt Text", encrypt_text, bg="#1565C0")
encrypt_btn.grid(row=0, column=0, padx=6, pady=4)

decrypt_btn = styled_button(btn_frame, "Decrypt Text", decrypt_text, bg="#2E7D32")
decrypt_btn.grid(row=0, column=1, padx=6, pady=4)

copy_btn = styled_button(btn_frame, "Copy", copy_to_clipboard, bg="#FFC107")
copy_btn.grid(row=0, column=2, padx=6, pady=4)

paste_btn = styled_button(btn_frame, "Paste", paste_from_clipboard, bg="#FF7043")
paste_btn.grid(row=0, column=3, padx=6, pady=4)

# ---- File operations frame (Fernet only)
file_frame = tk.Frame(root, bg="#121212")
file_frame.pack(fill=tk.X, padx=16, pady=(6, 12))

encrypt_file_btn = styled_button(file_frame, "Encrypt File (Fernet)", encrypt_file, bg="#8E24AA", width=20)
encrypt_file_btn.grid(row=0, column=0, padx=10)

decrypt_file_btn = styled_button(file_frame, "Decrypt File (Fernet)", decrypt_file, bg="#C62828", width=20)
decrypt_file_btn.grid(row=0, column=1, padx=10)

# ---- Footer / info
footer = tk.Label(
    root,
    text=(
        "Notes: Fernet is secure and supports files. Caesar/Substitution are classic ciphers for learning and text only.\n"
        "For Fernet, your 'Gate' is the only secret; choose the same for decryption."
    ),
    fg="#AFAFAF",
    bg="#121212",
    font=("Segoe UI", 9),
    justify=tk.CENTER,
)
footer.pack(side=tk.BOTTOM, pady=(0, 10))

# Initialize control states
update_controls()

# Run
root.mainloop()
