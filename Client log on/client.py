import socket
import key_handler
import message_loop_utils
import client_gui

def main():
    dilithium_object = key_handler.dilithium_key_gen()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(('localhost', 8080))

        server_keys = message_loop_utils.key_recv(sock)
        ciphertext, shared_secret = key_handler.kyber_encap_decap(
            server_keys['server_session_pub'], None, 'encap'
        )
        message_loop_utils.key_send(sock, dilithium_object, ciphertext)

        client_gui.start_GUI(
            sock=sock,
            client_dilithium_priv=dilithium_object['dilithium_priv_key'],
            shared_secret=shared_secret,
            server_dilithium_pub=server_keys['server_dilithium_pub_key']
        )

if __name__ == '__main__':
    main()
