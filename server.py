import socket
import threading
import key_handler
import message_loop_utils
import key_refresh

SERVER_IP = 'localhost' 
PORT = 8080

# Handles clients in a specific thread
def client_handler(client_socket, client_IP, dilithium_Key):
    timestamp, created = key_handler.key_time_stamp('session')  # Session timestamp
    kyber_keys = key_handler.kyber_key_gen()  # Dictionary of kyber keys
    print(f'{client_IP} session created at: {created}')

    threading.Thread(target=key_refresh.kyber_check, daemon=True, args=()).start()

    while True:
        try:
            # Receive encrypted message
            recv_data = message_loop_utils.recv_encrypted_message(
                client_socket,
                dilithium_Key['dilithium_pub_key'],
                shared_secret,
                timestamp
            )
            if recv_data is None or recv_data == b'':
                print(f"[DISCONNECTED] {client_IP} has disconnected.")
                break

            # Echo back or simulate response
            message_loop_utils.send_encrypted_message(
                client_socket,
                dilithium_Key['dilithium_priv_key'],
                shared_secret,
                recv_data
            )

        except (ConnectionResetError, BrokenPipeError) as e:
            print(f"[FORCE DISCONNECT] {client_IP} — {e}")
            break
        except Exception as e:
            print(f"[ERROR] Exception from {client_IP} — {e}")
            break

def main():
    dilithium_object = key_handler.dilithium_key_gen()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((SERVER_IP, PORT))
        server_socket.listen()
        print(f'[+] Server is Listening {SERVER_IP}:{PORT}')

        while True:
            client_socket, client_IP = server_socket.accept()
            threading.Thread(
                target=client_handler,
                daemon=True,
                args=(client_socket, client_IP, dilithium_object)
            ).start()

if __name__ == "__main__":
    main()
