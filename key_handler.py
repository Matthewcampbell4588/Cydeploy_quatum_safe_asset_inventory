import oqs
from datetime import datetime,timezone,timedelta
import message_loop_utils
import json

#creates a signiture with the message and dilithium private key *note message must be in bytes before signing*
def message_signing(dilithium_private_key,msg):
     #add dilithium check here to see if it needs to be renewed before the message is sent (take into consideration how it might update if there are mutiple clients)
    signiture  = dilithium_private_key.sign(msg)
    return signiture

#checks msg and signiture with dilithium public key
def message_verfication(msg,sig,dilithium_pub):
    with oqs.Signature('Dilithium2') as verify:
        is_valid = verify.verify(msg,sig,dilithium_pub)
    return is_valid

#Creates and formats dilithium keys also timestamps 
def dilithium_key_gen():
            diltium_kem =  oqs.Signature('Dilithium2')
            dilithium_public_key = diltium_kem.generate_keypair()
            timestamp,created = key_time_stamp('dilithium')
            dilithium_keys = {

            'dilithium_priv_key' : diltium_kem,
            'dilithium_pub_key' : dilithium_public_key,
             'created' : created,
             'expires' : timestamp

             }
            
            return dilithium_keys

#Timestamps utility keys kyber should expire after 1 hour and dilitihum should expire after a month
def key_time_stamp(option):
    try:
        if option == 'session':
            now = datetime.now(timezone.utc)
            return now
        elif option == 'dilithium':
            now = datetime.now(timezone.utc)
            expires = now + timedelta(days=30)
            return expires,now
    except Exception as e:
        print(f'Error at timestamp: {e}')

#Generates kyber key pairs
def kyber_key_gen():
    kem = oqs.KeyEncapsulation('Kyber512')
    kyber_pub_key = kem.generate_keypair()
    kyber_keys = {
        "session_pub" : kyber_pub_key,
        "session_priv" : kem
    }
    return kyber_keys

#Encaps or decaps key based on option 
def kyber_encap_decap(key,ciphertext,option):
     if option == 'encap':
          with oqs.KeyEncapsulation('Kyber512') as kem_encap:
            ciphertext, shared_secret = kem_encap.encap_secret(key)
            return ciphertext , shared_secret
          
     elif option == 'decap':
        shared_secret = key.decap_secret(ciphertext)#Here is where the shared secret is created and now both client and server have the same symmetric key
        key.free()
        return shared_secret

#these two are only used for intial exchange
def server_key_exchange(socket,dilithium_Key):
     kyber_keys = kyber_key_gen()
     message_loop_utils.key_send(socket,dilithium_Key,kyber_keys)
     client_keys = message_loop_utils.key_recv(socket)
     shared_secret = kyber_encap_decap(kyber_keys['session_priv'],client_keys['client_ciphertext'],'decap')
     return shared_secret, client_keys
    


def client_key_exchange(socket,dilithium_key):
    server_keys  = message_loop_utils.key_recv(socket)
    ciphertext , shared_secret = kyber_encap_decap(server_keys['server_session_pub'],None,'encap')
    message_loop_utils.key_send(socket,dilithium_key,ciphertext)
    return shared_secret, server_keys['server_dilithium_pub_key']
