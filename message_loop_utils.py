import json
import aes_encrypt
import key_handler

def recv_format(client_socket):
    msg_prefix = client_socket.recv(4)
    total_bytes = int.from_bytes(msg_prefix)
    remaining_bytes = total_bytes
    json_data = b''
    while remaining_bytes > 0:
        packet = client_socket.recv(remaining_bytes)
        json_data += packet
        remaining_bytes -= len(packet)
    data = json.loads(json_data.decode())
    return data

def send_format(client_socket, data):
    json_string = json.dumps(data)
    length = len(json_string.encode())
    msg_lenth  = length.to_bytes(4,'big')
    client_socket.send(msg_lenth)
    client_socket.send(json_string.encode())

def send_encrypted_message(client_socket, d_key, shared_secret, plaintext):
    ciphertext, iv = aes_encrypt.encrypt(plaintext, shared_secret)
    payload = {
        'ciphertext': ciphertext.hex(),
        'iv': iv.hex()
    }
    signature = key_handler.message_signing(d_key, json.dumps(payload).encode()) if d_key else None
    package = {
        'payload': payload,
        'sig': signature.hex() if signature else None
    }
    send_format(client_socket, package)

def recv_encrypted_message(client_socket, d_key, shared_secret):
    try:
        data = recv_format(client_socket)
        if d_key and not key_handler.message_verification(
            json.dumps(data['payload']).encode(),
            bytes.fromhex(data['sig']),
            d_key
        ):
            raise ValueError('Signature Verification Failed')
        ciphertext = bytes.fromhex(data['payload']['ciphertext'])
        iv = bytes.fromhex(data['payload']['iv'])
        plaintext = aes_encrypt.decrypt(ciphertext, shared_secret, iv)
        return plaintext
    except Exception as e:
        print(f'[ERROR] {e}')
