
# 🔐 Multi-Cipher Encryption Tool

📌 **Overview**


A professional-looking **Tkinter-based GUI tool** for text and file encryption.
Supports:

* **Fernet (Gate Key)** → Modern, secure symmetric encryption.
* **Caesar Cipher** → Classical shift cipher.
* **Substitution Cipher** → Fixed custom mapping cipher.

The app also includes **file encryption (Fernet only)**, **clipboard integration**, and a **dark-themed user interface**.

---

## ✨ Features

* Encrypt & decrypt text with **Fernet, Caesar, or Substitution**.
* Encrypt & decrypt files with **Fernet (Gate Key)**.
* Choose a **Gate** (AND, OR, XOR, NAND, NOR) → derives unique Fernet keys.
* Customize Caesar shift value.
* Clipboard buttons: **Copy / Paste** encrypted text.
* Clean **dark UI** with ttk comboboxes and styled buttons.

---

## 📂 File Structure

```
multi_cipher_tool.py   # Main Tkinter app (this file)
README.md              # Documentation
```

---

## 🖥️ User Interface Preview

* **Top Bar**: Cipher selector, Gate selector (for Fernet), Shift entry (for Caesar).
* **Main Area**: Large text box for entering plaintext/ciphertext.
* **Buttons**: Encrypt, Decrypt, Copy, Paste.
* **File Actions**: Encrypt/Decrypt files (Fernet only).
* **Footer Notes**: Reminders about cipher usage.

---

## 🚀 How to Run

1. Install dependencies:

```bash
pip install cryptography pyperclip
```

2. Run the app:

```bash
python multi_cipher_tool.py
```

---

## ⚡ Example Workflows

### Text Encryption (Caesar)

1. Select **Caesar Cipher**.
2. Enter message: `HELLO`.
3. Set shift = `3`.
4. Click **Encrypt Text** → `KHOOR`.
5. Click **Decrypt Text** → `HELLO`.

---

### Text Encryption (Fernet)

1. Select **Fernet (Gate Key)**.
2. Choose Gate: `XOR`.
3. Enter message: `Secret123`.
4. Click **Encrypt Text** → Encrypted blob.
5. To decrypt, select same Gate and paste the blob.

---

### File Encryption (Fernet only)

1. Select **Fernet (Gate Key)**.
2. Choose a Gate.
3. Click **Encrypt File (Fernet)** → choose file → saves as `.encrypted`.
4. Click **Decrypt File (Fernet)** → choose `.encrypted` file → saves as `.decrypted`.

---

## 📜 Notes

* **Fernet (Gate Key)** is secure and works for both text and files.
* **Caesar & Substitution** are **classical ciphers** — provided here for learning, not for security.
* The **Gate name** acts as your **secret key** for Fernet. Use the same gate for decryption.

---

## ✅ Requirements

* Python 3.x
* `cryptography`
* `pyperclip`

Install with:

```bash
pip install cryptography pyperclip
```

---
🧠 Summary

This tool combines **modern cryptography (Fernet)** with **classical ciphers (Caesar, Substitution)** in a single GUI.
It’s useful for:

* Learning encryption basics.
* Securing files with Fernet.
* Experimenting with Caesar and Substitution ciphers.

---

