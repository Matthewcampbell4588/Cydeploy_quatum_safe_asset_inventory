import socket
import threading
import oqs          
import json
from datetime import datetime,timezone,timedelta
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
import hashlib
#Dont use AI code here -- try and develope it yourself (only use it to clarify, but not code for you) 
#started at 7/9/2025 7:00pm 
#End at 7/9/2025 9:00pm   (change this everytime done coding)



SERVER_IP = 'localhost'
PORT = 8080

#Stores all public keys and shared_secrets in memory
server_keys = {}

#Encryption/Decryption Utilities
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
            return expires,
        elif option == 'dilithium':
            now = datetime.now(timezone.utc)
            expires = now + timedelta(days=30)
            return expires,now
    except Exception as e:
        print(f'Error: {e}')

#creates and timestamps dilithium keys
def dilithium_key_gen():
    with oqs.Signature('Dilithium2') as diltium_kem:
            dilithium_public_key = diltium_kem.generate_keypair()
            timestamp,created = key_time_stamp('dilithium')
            server_keys['Server_Dilithium_sig'] = {

            'dilithium_priv_key' : diltium_kem,
            'dilithium_pub_key' : dilithium_public_key,
             'created' : created,
             'expires' : timestamp

             }

#creates session kyber keys
def kyber_key_gen(client_IP):
    with oqs.KeyEncapsulation('Kyber512') as session_kem:
        session_public_key = session_kem.generate_keypair()
        kyber_data = {

            'session_pub' : session_public_key,
            'session_priv' : session_kem,
            
        }
        return kyber_data



#Key exchange: Grabs clients keys stores it in memory, then develops kyber session keys and send the dilithium and kyber public keys to client to complete the key exchange 
def key_exchange(client_socket,client_IP):
    try:
        kyber_keys = kyber_key_gen()
        #This is to check if the expiration of the dilithium key before sending it. If its expired it created a new set of keys 
        if server_keys['Server_Dilithium_sig']['timestamp'] < datetime.now(timezone.utc):
            dilithium_key_gen()
        
        client_package = {

            'server_Kyber_key':kyber_keys['session_pub'],
            'server_Dilithium_key': server_keys['Server_Dilithium_sig']['dilithium_pub_key']
        }

        data = json.dump(client_package) #packages into json format
        client_socket.send(data.encode()) #Send json of servers public key to client for encapsulation and signiture verification

        json_client_data = client_socket.recv(1024) #gets ciphertext and client dilithium public key
        client_data = json.load(json_client_data.decode()) #should be sent in json format to be later read as a dictionary. Stores ciphertext and dilithium public key
        shared_secret = kyber_keys['session_priv'].decap_secret((client_data['ciphertext']))#Here is where the shared secret is created and now both client and server have the same symmetric key
        


        client_keys = {

            'shared_secret' : shared_secret,
            'dilithium' : client_data['dilithium_pub_key']

        }
        print(f'{client_IP}')
        return client_keys 
    except Exception as e:
        print(f'Error: {e}')


#Handles clients in a specific thread. This also ensures the key exchange, data verification, data encryption and decryption. Along with any other feature need to complete the project goal
def client_handler(client_socket,client_IP):
    timestamp = key_time_stamp('session')
    #need user authentication 
    client_keys = key_exchange()


    #Will probably include message/recv loop
    while True:#checks session time to see if new keys are needed for the session
        if timestamp < datetime.now(timezone.utc):
           client_keys = key_exchange() 
        elif timestamp >= datetime.now(timezone.utc):
          pass  
        else:
            pass
        

def main():
    dilithium_key_gen()
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server_socket:
        server_socket.bind((SERVER_IP,PORT))
        server_socket.listen()
        print(f'[+] Server is Listening {SERVER_IP}:{PORT} ')
        while True:
           client_socket , client_IP = server_socket.accept()
           threading.Thread(target = client_handler , daemon=True , args = (client_socket, client_IP )).start()

