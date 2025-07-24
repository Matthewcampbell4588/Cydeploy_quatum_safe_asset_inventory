import socket
import key_handler
import message_loop_utils

client_keys = {}

def recv_loop():
    while True:
        pass

def send_loop():
    while True:
        pass

def main():
    dilithium_object = key_handler.dilithium_key_gen()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        client_socket.connect(('localhost', 8080))

        # Key exchange with server
        server_keys = key_handler.key_recv(client_socket)
        ciphertext, shared_secret = key_handler.kyber_encap_decap(
            server_keys['server_session_pub'],
            None,
            'encap'
        )

        # Send client keys to server
        message_loop_utils.key_send(client_socket, dilithium_object, ciphertext)

if __name__ == "__main__":
    main()
