import socket
import threading
import key_handler 
import message_loop_utils 
import key_refresh
import command_handler 
import random as k









SERVER_IP = 'localhost' 
PORT = 8080

connected_clients = []
clients_lock = threading.Lock()


#Handles clients in a specific thread. This also ensures the key exchange, data verification, data encryption and decryption. Along with any other feature need to complete the project goal
def client_handler(socket,client_IP,dilithium_Key):

    print(f'{client_IP} session created at: {key_handler.key_time_stamp('session')}')#logs client connection
    
    #three lines below is the initial key exchange 
    shared_secret, client_pub = key_handler.server_key_exchange(socket,dilithium_Key)#client_pub is the client pub dilitihum key this includes experation date
    print(f'Derived shared secret: {shared_secret}\n')
    kyber_key = threading.Thread(target=key_refresh.kyber_refresh_loop, args=(connected_clients, clients_lock), daemon=True).start()


    with clients_lock:
        connected_clients.append({
            "sock": socket,
            "shared_secret": shared_secret,
            "client_pub": client_pub
        })

    
    try:
        while True:
            recv_data = message_loop_utils.recv_encrypted_message(socket,client_pub,shared_secret)

            if recv_data == b'':
                print(f"[DISCONNECTED] {client_IP} closed connection.")
                break

            print(f"[{client_IP}] {recv_data}")

            if recv_data.get('type') == 'command_req':
                try:
                    if recv_data['command'] == 'video':
                        data = {
                            'type': 'command_reponse',
                            'action': 'video',
                            'command': 'https://www.youtube.com/watch?v=tCHYrpiqDxI'
                        }
                    elif recv_data['command'] == 'message':
                        data = {
                            'type': 'command_reponse',
                            'action': 'message',
                            'command': 'Hello World'
                        }
                    elif recv_data['command'] == 'rand num':
                        data = {
                            'type': 'command_reponse',
                            'action': 'rand num',
                            'command': k.randint(1, 10)
                        }
                    else:
                        raise AssertionError('Invalid Command')
                except AssertionError as e:
                    print(f'[-] ERROR: {e}')
                    continue

                command_handler.command_controller(data,dilithium_Key['dilithium_priv_key'],shared_secret,socket)
            elif recv_data.get('type') == 'kyber_refresh':
                # Decapsulate to get new shared secret
                new_secret = key_handler.kyber_encap_decap(kyber_key,bytes.fromhex(recv_data['ciphertext']),'decap' )
                shared_secret = new_secret  # Update local var

                # Update in connected_clients list
                with clients_lock:
                    for client in connected_clients:
                        if client["sock"] == socket:
                            client["shared_secret"] = new_secret
                            break
            elif recv_data.get('type') == 'dilithium_refresh_request':
                with clients_lock:
                    for entry in connected_clients:
                        if entry["sock"] == socket:
                            entry["client_pub"] = bytes.fromhex(recv_data['dilithium_pub_key'])
                            entry["client_expiration"] = bytes.fromhex(recv_data['expiration'])
                            break

    except (ConnectionResetError, BrokenPipeError):
        print(f"[FORCE DISCONNECT] {client_IP}")
    except Exception as e:
        print(f"[ERROR] Exception from {client_IP} — {e}")
    finally:
        with clients_lock:
            connected_clients[:] = [c for c in connected_clients if c["sock"] != socket]
        socket.close()


    

def main():

    dilithium_object = key_handler.dilithium_key_gen()#first global gen of dilithium keys
    threading.Thread(target=key_refresh.server_dilithium_refresh,daemon=True, args=(dilithium_object, connected_clients, clients_lock)).start()#thread to check server keys
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:#creates a server socket
        sock.bind((SERVER_IP,PORT))#binds server Ip and port
        sock.listen()
        print(f'[+] Server is Listening {SERVER_IP}:{PORT} ')
        while True:
           client_socket , client_IP = sock.accept()#accetps client connection
           threading.Thread(target = client_handler , daemon=True , args = (client_socket, client_IP, dilithium_object )).start()#creates a client thread
        
main()