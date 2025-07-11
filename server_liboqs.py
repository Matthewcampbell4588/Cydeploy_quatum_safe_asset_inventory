import socket
import threading
import oqs          
import json
from datetime import datetime,timezone,timedelta
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
import hashlib




SERVER_IP = 'localhost'
PORT = 8080

#Stores all public keys and shared_secrets in memory


#Encryption/Decryption Utilities (can make into own class for less code on server and client)
#Padding function ensures that the message fits the 128bit block aes encrypts in
def pad(data):
    padder = padding.PKCS7(128).padder()
    return padder.update(data) + padder.finalize()

#unpads data in decryption to reveal plaintext, since its padded during encryption
def unpad(data):
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(data) + unpadder.finalize()

#Encryption function that takes in the data and the shared_secret to encrypt the data it returns a ciphertext and the initial vector (for CBC) used during the encryption
def encrypt(data, key):
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))#uses 
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(pad(data)) + encryptor.finalize()
    return iv, ciphertext
#Decryption Function: Takes in ciphertext, servers decap Shared secret(uses private key, so client-->server shared secret), and intial vector 
def decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(plaintext_padded)

#timestamps keys kyber should expire after 1 hour and dilitihum should expire after a month
def key_time_stamp(option):
    try:
        if option == 'session':
            now = datetime.now(timezone.utc)
            expires = now + timedelta(hours=1)
            return expires,now
        elif option == 'dilithium':
            now = datetime.now(timezone.utc)
            expires = now + timedelta(days=30)
            return expires,now
    except Exception as e:
        print(f'Error at timestamp: {e}')

#creates and timestamps dilithium keys
def dilithium_key_gen():
    with oqs.Signature('Dilithium2') as diltium_kem:
            dilithium_public_key = diltium_kem.generate_keypair()
            timestamp,created = key_time_stamp('dilithium')
            dilithium_keys = {

            'dilithium_priv_key' : diltium_kem,
            'dilithium_pub_key' : dilithium_public_key,
             'created' : created,
             'expires' : timestamp

             }
            
    return dilithium_keys

#creates session kyber keys
def kyber_key_gen():
    session_kem = oqs.KeyEncapsulation('Kyber512') 
    session_public_key = session_kem.generate_keypair()
    kyber_data = {

            'session_pub' : session_public_key,
            'session_priv' : session_kem,

        }
    return kyber_data
    
def recv_loop(client_socket):
    msg_prefix = client_socket.recv(4)#Gets server keys
    total_bytes = int.from_bytes(msg_prefix)
    remaining_bytes = total_bytes
    json_data = b''

    while remaining_bytes > 0:
        packet = client_socket.recv(remaining_bytes)
        json_data += packet
        remaining_bytes = remaining_bytes - len(packet)
    data = json.loads(json_data.decode())
    return data

def send_to_client(client_socket , data):
    json_string = json.dumps(data)
    #Grabs json length
    length = len(json_string.encode())  
    #converts int to binary rep so that it can be sent to the client 
    msg_lenth  = length.to_bytes(4,'big')
    #Sending how long the msg will be to the client so that when sending the json file it knows when to stop. Based on what I implmented on client end
    client_socket.send(msg_lenth)
    client_socket.send(json_string.encode())


#Key exchange: Grabs clients keys stores it in memory, then develops kyber session keys and send the dilithium and kyber public keys to client to complete the key exchange 
def key_exchange(client_socket,dilithium_keys):
    try:
        kyber_keys = kyber_key_gen()
        #This is to check if the expiration of the dilithium key before sending it. If its expired it created a new set of keys 
        if dilithium_keys['expires'] < datetime.now(timezone.utc):
            dilithium_keys = dilithium_key_gen()
            print('Servers Dilithium keys renewed')

        #Stores kyber and dilithium pub keys
        client_to_server_package = {

            'server_Kyber_key':kyber_keys['session_pub'].hex(),
            'server_Dilithium_key': dilithium_keys['dilithium_pub_key'].hex()

        }
        send_to_client(client_socket,client_to_server_package)

        client_data = recv_loop(client_socket)
        print(f'Client data: {client_data}')

        shared_secret = kyber_keys['session_priv'].decap_secret((bytes.fromhex(client_data['shared_ciphertext'])))#Here is where the shared secret is created and now both client and server have the same symmetric key
        kyber_keys['session_priv'].free()
        print(f'This is the server dervided secret: {shared_secret}')
        #stores shared secret from decap and the clients public dilithium key
        keys = {

            'shared_secret' : shared_secret,
            'dilithium' : bytes.fromhex(client_data['Dilithium_pub_key'])

        }
    
        print(f'\n\nkeys: {keys}')
        return keys 
    except Exception as e:
        print(f'Error at exchange: {e}')


#Handles clients in a specific thread. This also ensures the key exchange, data verification, data encryption and decryption. Along with any other feature need to complete the project goal
def client_handler(client_socket,client_IP,dilithium_Key):

    timestamp,created = key_time_stamp('session')
    print(f'{client_IP} session created at: {created}')
    #need user authentication 
    client_keys = key_exchange(client_socket,dilithium_Key)
    print('\n\nKey Exchange done')
    #Test to see if it gets encrypted data and converts it to plaintext
    data = recv_loop(client_socket)
    print()
    print(f'\n\nEncrypted data: {data}')
    plaintext = decrypt(bytes.fromhex(data['ciphertext']),client_keys['shared_secret'],bytes.fromhex(data['iv']))
    print(plaintext)

    
    
        

def main():
    dilithium_object = dilithium_key_gen()
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server_socket:
        server_socket.bind((SERVER_IP,PORT))
        server_socket.listen()
        print(f'[+] Server is Listening {SERVER_IP}:{PORT} ')
        while True:
           client_socket , client_IP = server_socket.accept()
           threading.Thread(target = client_handler , daemon=True , args = (client_socket, client_IP,dilithium_object )).start()

main()