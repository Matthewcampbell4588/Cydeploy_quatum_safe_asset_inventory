import socket
import threading
import key_handler 
import message_loop_utils 
import key_refresh
import command_handler 
import random



commands = {


        'video' : 'hello' ,
        'message' : 'Hello World',
        'rand num' : random.range(100)

}



SERVER_IP = 'localhost' 
PORT = 8080



#Handles clients in a specific thread. This also ensures the key exchange, data verification, data encryption and decryption. Along with any other feature need to complete the project goal
def client_handler(socket,client_IP,dilithium_Key):
    timestamp,created = key_handler.key_time_stamp('session')#Session timestamp
    kyber_keys = key_handler.kyber_key_gen()#gets a dic of kyber keys check key_handler for format
    print(f'{client_IP} session created at: {created}')#logs on server
    #three lines below is the initial key exchange 
    message_loop_utils.key_send(socket,dilithium_Key,kyber_keys)
    Client_shared_keys = message_loop_utils.key_recv(socket)
    shared_secret = key_handler.kyber_encap_decap(kyber_keys['session_priv'],Client_shared_keys['client_ciphertext'],'decap')
    print(shared_secret)
    #threading.Thread(target = key_refresh.key_check, daemon = True, args = ()).start()# this thread will be where its constantly checking the keys (second way of checking, might be more resource intensive depending on the amount of agents or clients )
    
    while True:
        try:
            #gets data here 
            recv_data = message_loop_utils.recv_encrypted_message(socket,dilithium_Key['dilithium_pub_key'],shared_secret,timestamp)
            #checks to see if client is still connected since if it disconnects it will send a None or b'' to the recv
            if recv_data == b'':
                print(f"[DISCONNECTED] {client_IP} has disconnected.")
                break#exits loop on graceful shutdown

            #checks data
            if recv_data['command'] == 'video':
                data = {
                    'type' : 'command',
                    'command' : commands['video']
                }
            elif recv_data['command'] == 'message':
                data = {
                    'type' : 'command',
                    'command' : commands['message']
                }
            elif recv_data['command'] == 'rand num':
                data = {
                    'type' : 'command',
                    'command' : commands['rand num']
                }
            else:
                raise ValueError("ERROR: INVALID COMMAND")

            #sends command to client
            command_handler.commands(data,dilithium_Key['dilithium_priv_key'])


            #Here is where the session loop should break if the client disconnects
        except (ConnectionResetError, BrokenPipeError) as e:
            print(f"[FORCE DISCONNECT] {client_IP} — {e}")
            break  # Exit loop on abrupt disconnection
        except Exception as e:
            print(f"[ERROR] Exception from {client_IP} — {e}")
            break  # Exit loop on unexpected errors


    

def main():

    dilithium_object = key_handler.dilithium_key_gen()
    
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        sock.bind((SERVER_IP,PORT))
        sock.listen()
        print(f'[+] Server is Listening {SERVER_IP}:{PORT} ')
        while True:
           client_socket , client_IP = sock.accept()
           threading.Thread(target = client_handler , daemon=True , args = (client_socket, client_IP,dilithium_object )).start()

main()