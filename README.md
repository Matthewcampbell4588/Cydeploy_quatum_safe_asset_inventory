# Kyber-AES Authentication System

This is a secure client-server login system that uses post-quantum cryptographic algorithms and symmetric encryption. It includes:

- **Kyber512** for key exchange (post-quantum)
- **AES-256-CBC** for secure message encryption
- **Dilithium2** for digital signatures
- **SHA-256** for credential hashing
- **Time-based access restriction** (9 AM – 5 PM)

## 🗂 Files

- `client.py` — Entry point for the client
- `server.py` — Starts the server and handles clients
- `auth_client.py` — Client-side login logic with time restrictions
- `auth_server.py` — Server-side login logic and password validation
- `key_handler.py` — Handles key generation and crypto utilities
- `aes_encrypt.py` — AES-256 encryption and decryption
- `message_loop_utils.py` — Message sending/receiving with encryption and signing
- `users.txt` — Sample hashed user credentials

## 🔐 users.txt Format

Each line contains:

```
<hashed_username>,<hashed_password>,<last_password_reset_date>
```

Example:
```
1a79a4d60de6718e8e5b326e338ae533,5f4dcc3b5aa765d61d8327deb882cf99,2025-06-01
```

> You can generate your own SHA-256 hashes using Python’s hashlib.

## ▶ How to Run

### 1. Install Requirements

```bash
pip install oqs-python requests cryptography
```

### 2. Start the Server

```bash
python server.py
```

### 3. Run the Client (in another terminal)

```bash
python client.py
```

### 4. Login Flow

- If login is outside 9–5 or credentials are wrong/expired, access will be denied.
- If successful, the server will respond with `LOGIN_SUCCESS`.

## ✅ Notes

- Make sure `users.txt` exists in the same directory.
- All messages are encrypted with AES and signed using Dilithium for authenticity.

## 📌 Dependencies

- [oqs-python](https://github.com/open-quantum-safe/liboqs-python)
- `cryptography`, `requests`

---

Created for secure post-quantum authentication demo.
