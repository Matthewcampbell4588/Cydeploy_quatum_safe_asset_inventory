import hashlib
import json
from datetime import datetime
from message_loop_utils import send_encrypted_message, recv_encrypted_message

def load_users():
    users = {}
    with open("users.txt", "r") as f:
        for line in f:
            u_hash, p_hash, reset = line.strip().split(",")
            users[u_hash] = (p_hash, reset)
    return users

def check_password_expired(reset_str):
    reset_date = datetime.strptime(reset_str, "%Y-%m-%d")
    return (datetime.now() - reset_date).days > 90

def is_within_allowed_time():
    now = datetime.now().time()
    return datetime.strptime("09:00", "%H:%M").time() <= now <= datetime.strptime("17:00", "%H:%M").time()

def handle_login(client_socket, client_dilithium_key, shared_secret):
    data = recv_encrypted_message(client_socket, client_dilithium_key, shared_secret)
    creds = json.loads(data.decode())

    users = load_users()
    u_hash = creds["username"]
    p_hash = creds["password"]

    if u_hash in users:
        stored_p, reset = users[u_hash]
        if stored_p == p_hash:
            if check_password_expired(reset):
                send_encrypted_message(client_socket, None, shared_secret, b"LOGIN_FAIL: PASSWORD EXPIRED")
                return False

            if not is_within_allowed_time():
                send_encrypted_message(client_socket, None, shared_secret, b"LOGIN_DENIED: OUTSIDE HOURS")
                return False

            send_encrypted_message(client_socket, None, shared_secret, b"LOGIN_SUCCESS")
            return True

    send_encrypted_message(client_socket, None, shared_secret, b"LOGIN_FAIL")
    return False
