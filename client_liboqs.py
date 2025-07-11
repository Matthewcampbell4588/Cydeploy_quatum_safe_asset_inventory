import oqs
import socket
import json
from datetime import datetime,timezone,timedelta
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets


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
            client_keys = {

            'dilithium_priv_key' : diltium_kem,
            'dilithium_pub_key' : dilithium_public_key,
             'created' : now,
             'expires' : timestamp

             }
            
    return client_keys

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

def send_to_server(client_socket , data):
    json_string = json.dumps(data)
    #Grabs json length
    length = len(json_string.encode())  
    #converts int to binary rep so that it can be sent to the client 
    msg_lenth  = length.to_bytes(4,'big')
    print(f'Message header length; {msg_lenth}')
    #Sending how long the msg will be to the client so that when sending the json file it knows when to stop. Based on what I implmented on client end
    client_socket.send(msg_lenth)
    client_socket.send(json_string.encode())

def key_exchange(client_socket,dilithium_keys):
    try:
        #This is to check if the expiration of the dilithium key before sending it. If its expired it created a new set of keys 
        if dilithium_keys['expires'] < datetime.now(timezone.utc):
            dilithium_keys = dilithium_key_gen()

        #Might make into its own function for recving key data
        
        server_data = recv_loop(client_socket)
        
        print(server_data)


        with oqs.KeyEncapsulation('Kyber512') as client_kem:
            ciphertext , shared_secret = client_kem.encap_secret(bytes.fromhex(server_data['server_Kyber_key']))
            print(f'This is the client dervided secret: {shared_secret}')


        client_to_server_package = {

            'Dilithium_pub_key': dilithium_keys['dilithium_pub_key'].hex(),
            'shared_ciphertext': ciphertext.hex()
        }

        send_to_server(client_socket,client_to_server_package)
        
        keys = {

            'shared_secret' : shared_secret,
            'dilithium' : bytes.fromhex(server_data['server_Dilithium_key'])

        }
        print(f'Keys Exchanged:{keys}')
        print(shared_secret)
        return keys
        
    except Exception as e:
        print(f'Error: {e}')


def main():
    msg = b'please work :('
    dilithium_object = dilithium_key_gen()
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as client_socket:
        client_socket.connect(('localhost',8080))
        keys = key_exchange(client_socket,dilithium_object)
        ciphertext , iv = encrypt(msg,keys['shared_secret'])
        
        encryption_data = {

            'ciphertext' : ciphertext.hex(),
            'iv': iv.hex()
        }

        send_to_server(client_socket,encryption_data)

main()

