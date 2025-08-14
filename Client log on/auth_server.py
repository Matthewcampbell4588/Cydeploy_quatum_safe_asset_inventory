import hashlib
import json
from datetime import datetime
from message_loop_utils import send_encrypted_message, recv_encrypted_message

def load_users():
    users = {}
    with open("users.txt", "r") as f:
        for line in f:
            parts = line.strip().split(",")
            if len(parts) == 4:
                u_hash, p_hash, reset, role = parts
                users[u_hash] = (p_hash, reset, role)
            else:
                u_hash, p_hash, reset = parts
                users[u_hash] = (p_hash, reset, "guest")
    return users

def check_password_expired(reset_str):
    reset_date = datetime.strptime(reset_str, "%Y-%m-%d")
    return (datetime.now() - reset_date).days > 90

def is_within_allowed_time():
    now = datetime.now().time()
    return datetime.strptime("09:00", "%H:%M").time() <= now <= datetime.strptime("17:00", "%H:%M").time()

def handle_login(client_socket, client_dilithium_key, shared_secret):
    data = recv_encrypted_message(client_socket, client_dilithium_key, shared_secret)
    creds = json.loads(data)

    users = load_users()
    u_hash = creds["username"]
    p_hash = creds["password"]

    if u_hash in users:
        stored_p, reset, role = users[u_hash]
        if stored_p == p_hash:
            if check_password_expired(reset):
                send_encrypted_message(client_socket, None, shared_secret, {"status": "FAIL", "message": "PASSWORD EXPIRED"})
                return False
            if not is_within_allowed_time():
                send_encrypted_message(client_socket, None, shared_secret, {"status": "FAIL", "message": "OUTSIDE LOGIN HOURS"})
                return False
            send_encrypted_message(client_socket, None, shared_secret, {"status": "SUCCESS", "role": role})
            return True

    send_encrypted_message(client_socket, None, shared_secret, {"status": "FAIL", "message": "INVALID CREDENTIALS"})
    return False
