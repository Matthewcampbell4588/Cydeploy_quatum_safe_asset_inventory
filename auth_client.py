import hashlib
import json
from datetime import datetime, time
from message_loop_utils import send_encrypted_message, recv_encrypted_message

def hash_sha256(data):
    return hashlib.sha256(data.encode()).hexdigest()

def is_within_allowed_time():
    now = datetime.now().time()
    return time(9, 0) <= now <= time(17, 0)

def login(client_socket, shared_secret, server_dilithium_key):
    if not is_within_allowed_time():
        print("[ACCESS DENIED] Outside allowed login hours.")
        return

    username = input("Username: ")
    password = input("Password: ")

    payload = {
        "username": hash_sha256(username),
        "password": hash_sha256(password)
    }

    plaintext = json.dumps(payload).encode()
    send_encrypted_message(client_socket, None, shared_secret, plaintext)

    result = recv_encrypted_message(client_socket, server_dilithium_key, shared_secret)
    print("[Server Response]", result.decode())
