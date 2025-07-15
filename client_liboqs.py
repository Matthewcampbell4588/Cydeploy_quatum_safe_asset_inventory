import socket
import aes_encrpyt
import key_handler
import send_recv
client_keys = {}







def main():
    dilithium_object = key_handler.dilithium_key_gen()
   
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as client_socket:
        client_socket.connect(('localhost',8080))

        #Here is the clients working example of the key exchange and message sig verfication 
        server_keys  = key_handler.key_recv(client_socket)
        ciphertext , shared_secret = key_handler.kyber_encap_decap(server_keys['server_session_pub'],None,'encap')
        key_handler.key_send(client_socket,dilithium_object,ciphertext)
        server_data = send_recv.recv(client_socket)
        print(f'signed message data: {server_data}')
        is_valid = key_handler.message_verfication(bytes.fromhex(server_data['msg']),bytes.fromhex(server_data['sig']),server_keys['server_dilithium_pub_key'])
        
        if is_valid == True:
            print('Works')
        else:
            print('fix it')
        

main()

