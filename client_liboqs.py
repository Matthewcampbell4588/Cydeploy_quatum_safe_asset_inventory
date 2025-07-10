import oqs
import socket
import json
from datetime import datetime,timezone,timedelta
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets

#Dont use AI code here -- try and develope it yourself (only use it to clarify, but not code for you)
#started at 7/9/2025 7:00pm
#End at 7/9/2025 (change this everytime done coding)

client_keys = {}



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


#Creates dilithium key pair, timestamps it with expiration date. then stores it in memory
def dilithium_key_gen():
    with oqs.Signature('Dilithium2') as diltium_kem:
            dilithium_public_key = diltium_kem.generate_keypair()
            now = datetime.now(timezone.utc)
            timestamp = now + timedelta(days=30)
            client_keys['Client_Dilithium_sig'] = {

            'dilithium_priv_key' : diltium_kem,
            'dilithium_pub_key' : dilithium_public_key,
             'created' : now,
             'expires' : timestamp
             
             }



def key_exchange(client_socket):
    try:
        #This is to check if the expiration of the dilithium key before sending it. If its expired it created a new set of keys 
        if client_keys['Server_Dilithium_sig']['timestamp'] < datetime.now(timezone.utc):
            dilithium_key_gen()
        raw_server_data = client_socket.recv(1024)#Gets server keys
        server_data = json.load(raw_server_data.decode())


        with oqs.KeyEncapsulation('Kyber512') as client_kem:
            pass

        server_to_client_package = {

            'server_Dilithium_key': client_keys['Server_Dilithium_sig']['dilithium_pub_key'],
            'server_Kyber_key': server_data['server_Kyber_key']
        }

        data = json.dump(client_package) #packages into json format
        client_socket.send(data.encode()) #Send json of servers public key to client for encapsulation and signiture verification
        json_client_data = client_socket.recv(1024) #gets ciphertext and client dilithium public key
        shared_secret = kyber_keys['session_priv'].decap_secret((server_to_client_package['ciphertext']))#Here is where the shared secret is created and now both client and server have the same symmetric key
        
        client_keys = {

            'shared_secret' : shared_secret,
            'dilithium' : client_keys['client_Dilithium_sig']['dilithium_pub_key']

        }

        return client_keys
        
    except Exception as e:
        print(f'Error: {e}')


def main():
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as client_socket:
        client_socket.connect(('localhost',8080))
        key_exchange(client_socket)


main()
