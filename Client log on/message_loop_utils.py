import json
import aes_encrpyt
import key_handler

def recv_format(socket):
    msg_prefix = socket.recv(4)
    total_bytes = int.from_bytes(msg_prefix)
    remaining_bytes = total_bytes
    json_data = b''

    while remaining_bytes > 0:
        packet = socket.recv(remaining_bytes)
        json_data += packet
        remaining_bytes -= len(packet)

    return json.loads(json_data.decode())

def send_format(socket, data):
    json_string = json.dumps(data)
    msg_length = len(json_string.encode()).to_bytes(4, 'big')
    socket.send(msg_length)
    socket.send(json_string.encode())

def send_encrypted_message(socket, d_key, shared_secret, plaintext):
    plaintext = json.dumps(plaintext)
    ciphertext, iv = aes_encrpyt.encrypt(plaintext.encode(), shared_secret)
    payload = {
        'ciphertext': ciphertext.hex(),
        'iv': iv.hex()
    }
    signature = key_handler.message_signing(d_key, json.dumps(payload, sort_keys=True).encode()) if d_key else b''
    package = {
        'payload': payload,
        'sig': signature.hex()
    }
    send_format(socket, package)

def recv_encrypted_message(socket, d_key, shared_secret):
    data = recv_format(socket)
    is_valid = key_handler.message_verification(
        json.dumps(data['payload'], sort_keys=True).encode(),
        bytes.fromhex(data['sig']),
        d_key
    ) if d_key else True
    if not is_valid:
        raise ValueError("Signature Verification Failed")
    plaintext = aes_encrpyt.decrypt(
        bytes.fromhex(data['payload']['ciphertext']),
        shared_secret,
        bytes.fromhex(data['payload']['iv'])
    )
    return json.loads(plaintext)

def key_send(socket, dilithium_keys, key):
    if isinstance(key, dict) and 'session_pub' in key:
        package = {
            'server_session_pub': key['session_pub'].hex(),
            'server_dilithium_pub_key': dilithium_keys['dilithium_pub_key'].hex()
        }
    elif isinstance(key, bytes):
        package = {
            'ciphertext': key.hex(),
            'client_dilithium_pub_key': dilithium_keys['dilithium_pub_key'].hex()
        }
    else:
        raise ValueError("Invalid Key format to key_send()")
    send_format(socket, package)

def key_recv(socket):
    data = recv_format(socket)
    if 'server_session_pub' in data:
        return {
            'server_session_pub': bytes.fromhex(data['server_session_pub']),
            'server_dilithium_pub_key': bytes.fromhex(data['server_dilithium_pub_key'])
        }
    elif 'ciphertext' in data:
        return {
            'client_ciphertext': bytes.fromhex(data['ciphertext']),
            'client_dilithium_pub_key': bytes.fromhex(data['client_dilithium_pub_key'])
        }
    else:
        raise ValueError("Received unknown key format")
