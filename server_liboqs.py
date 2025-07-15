import socket
import threading
import key_handler
import aes_encrpyt
from datetime import datetime,timezone,timedelta
import send_recv


SERVER_IP = 'localhost' 
PORT = 8080



#Handles clients in a specific thread. This also ensures the key exchange, data verification, data encryption and decryption. Along with any other feature need to complete the project goal
def client_handler(client_socket,client_IP,dilithium_Key):
    timestamp,created = key_handler.key_time_stamp('session')#Session timestamp
    msg = "Hello World".encode()
    kyber_keys = key_handler.kyber_key_gen()#gets a dic of kyber keys check key_handler for format
    print(f'{client_IP} session created at: {created}')#logs on server

    
    #everything below is a working example of key exchange and key signing 
    key_handler.key_send(client_socket,dilithium_Key,kyber_keys)
    client_keys  = key_handler.key_recv(client_socket)
    shared_secret = key_handler.kyber_encap_decap(kyber_keys['session_priv'],client_keys['client_ciphertext'],'decap')
    sig = key_handler.message_signing(dilithium_Key,msg)
    #package sent to client for verfication
    package = {

        'msg' : msg.hex(),
        'sig' : sig.hex(),
    }
    send_recv.send(client_socket,package)

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