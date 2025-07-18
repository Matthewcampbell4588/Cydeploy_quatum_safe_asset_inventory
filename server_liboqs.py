import socket
import threading
import key_handler
import message_loop_utils
import key_refresh





SERVER_IP = 'localhost' 
PORT = 8080


#Handles clients in a specific thread. This also ensures the key exchange, data verification, data encryption and decryption. Along with any other feature need to complete the project goal
def client_handler(client_socket,client_IP,dilithium_Key):
    timestamp,created = key_handler.key_time_stamp('session')#Session timestamp
    kyber_keys = key_handler.kyber_key_gen()#gets a dic of kyber keys check key_handler for format
    print(f'{client_IP} session created at: {created}')#logs on server
    threading.Thread(target = key_refresh.kyber_check, daemon = True, args = ()).start()
    while True:
        try:
            #gets data here 
            recv_data = message_loop_utils.recv_encrypted_message(client_socket,dilithium_Key['dilithium_pub_key'],shared_secret,timestamp)
            #checks to see if client is still connected since if it disconnects it will send a None or b'' to the recv
            if recv_data is None or recv_data == b'':
                print(f"[DISCONNECTED] {client_IP} has disconnected.")
                break#exits loop on graceful shutdown
            #have it recv data then later go through the dic to see what exactly needs to be sent back(ex what command can we simulate that can execute on the client)
            #Here is where we should send it
            message_loop_utils.send_encrypted_message(client_socket,dilithium_Key['dilithium_priv_key'],shared_secret,data)
            #Here is where the session loop should break if the client disconnects

        except (ConnectionResetError, BrokenPipeError) as e:
            print(f"[FORCE DISCONNECT] {client_IP} — {e}")
            break  # Exit loop on abrupt disconnection
        except Exception as e:
            print(f"[ERROR] Exception from {client_IP} — {e}")
            break  # Exit loop on unexpected errors

        pass

    
    

def main():

    dilithium_object = key_handler.dilithium_key_gen()
    
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server_socket:
        server_socket.bind((SERVER_IP,PORT))
        server_socket.listen()
        print(f'[+] Server is Listening {SERVER_IP}:{PORT} ')
        while True:
           client_socket , client_IP = server_socket.accept()
           threading.Thread(target = client_handler , daemon=True , args = (client_socket, client_IP,dilithium_object )).start()

main()