from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import secrets
import key_handler


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
    print('encrypted Data')
    #print(f'[DEBUG] ciphertext: {ciphertext}, Key: {key}, iv: {iv}')
    return ciphertext, iv

#Decryption Function: Takes in ciphertext, servers decap Shared secret(uses private key, so client-->server shared secret), and intial vector 
def decrypt(ciphertext, key, iv):
    #print(f'[DEBUG] ciphertext: {ciphertext}, Key: {key}, iv: {iv}')
    cipher = Cipher(algorithms.AES256(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
    print('data decrypted')
    return unpad(plaintext_padded)

