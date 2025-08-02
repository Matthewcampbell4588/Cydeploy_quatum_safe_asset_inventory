import socket
import threading
import key_handler
import message_loop_utils
import auth_server

SERVER_IP = 'localhost'
PORT = 8080

def client_handler(sock, client_IP, server_dilithium_key):
    timestamp, created = key_handler.key_time_stamp('session')
    kyber_keys = key_handler.kyber_key_gen()
    print(f"[+] Session started with {client_IP} at {created}")

    message_loop_utils.key_send(sock, server_dilithium_key, kyber_keys)
    client_keys = message_loop_utils.key_recv(sock)
    shared_secret = key_handler.kyber_encap_decap(
        kyber_keys['session_priv'],
        client_keys['client_ciphertext'],
        'decap'
    )

    login_success = auth_server.handle_login(
        sock,
        client_keys['client_dilithium_pub_key'],
        shared_secret
    )

    if not login_success:
        print(f"[DENIED] Login failed for {client_IP}")
        sock.close()
        return

    while True:
        try:
            recv_data = message_loop_utils.recv_encrypted_message(
                sock,
                client_keys['client_dilithium_pub_key'],
                shared_secret
            )

            if not recv_data:
                print(f"[DISCONNECTED] {client_IP} disconnected.")
                break

            print(f"[DATA] Received from {client_IP}: {recv_data}")

            data = {
                "type": "command_response",
                "status": "OK",
                "message": "You are logged in securely!"
            }
            message_loop_utils.send_encrypted_message(
                sock,
                server_dilithium_key['dilithium_priv_key'],
                shared_secret,
                data
            )

        except (ConnectionResetError, BrokenPipeError):
            print(f"[FORCED DISCONNECT] {client_IP} connection lost.")
            break
        except Exception as e:
            print(f"[ERROR] Unexpected exception from {client_IP}: {e}")
            break

def main():
    server_dilithium_key = key_handler.dilithium_key_gen()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((SERVER_IP, PORT))
        sock.listen()
        print(f"[+] Server listening on {SERVER_IP}:{PORT}")
        while True:
            client_socket, client_address = sock.accept()
            print(f"[CONNECTED] {client_address} connected.")
            threading.Thread(
                target=client_handler,
                daemon=True,
                args=(client_socket, client_address, server_dilithium_key)
            ).start()

if __name__ == '__main__':
    main()
