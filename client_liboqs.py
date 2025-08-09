import socket
import key_handler
import client_gui
keys = {

}






def main():
    dilithium_object = key_handler.dilithium_key_gen()
    
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        sock.connect(('localhost',8080))
        shared_secret , server_dilithium_key = key_handler.client_key_exchange(sock,dilithium_object)
        print(f'Derived shared secret: {shared_secret}\n')
        client_gui.start_GUI(sock, dilithium_object['dilithium_priv_key'], shared_secret, server_dilithium_key)
        
main()

