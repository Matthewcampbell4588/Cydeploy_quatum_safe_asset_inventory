import oqs
from datetime import datetime,timezone,timedelta
import message_loop_utils
import json

#creates a signiture with the message and dilithium private key *note message must be in bytes before signing*
def message_signing(dilithium_private_key,msg):
    dilithium_priv = dilithium_private_key['dilithium_priv_key']
     #add dilithium check here to see if it needs to be renewed before the message is sent (take into consideration how it might update if there are mutiple clients)
    signiture  = dilithium_priv.sign(msg)
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
            expires = now + timedelta(hours=1)
            return expires,now
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



#Exchange Utilities
# key_sends formats the data correctly to be sent to either client or server 
def key_send(client_socket,dilithium_keys,key):
        

        if isinstance(key,dict) and 'session_pub' in key:
            #Stores kyber and dilithium pub keys from server to send to client
            package = {

                'server_session_pub':key['session_pub'].hex(),
                'server_dilithium_pub_key': dilithium_keys['dilithium_pub_key'].hex()
            }
        elif isinstance(key,bytes):
            package = {
                    'ciphertext' : key.hex() ,
                    'client_dilithium_pub_key':dilithium_keys['dilithium_pub_key'].hex()
             }
            #stores what the client would generate to send to server
        else:
             raise ValueError('Invalid Key format to key_send()')
        
        #Send to client or server
        message_loop_utils.send(client_socket,package)
        
#recvs data and formats its from hex to bytes and stores it checks if it comes from client or server
def key_recv(client_socket):
        #returns the correctly formmated data from client 
        data = message_loop_utils.recv(client_socket)

        #checks if it is coming from server 
        if 'server_session_pub' in data:
        # This formats the package from the server for the client
            keys = {
            'server_session_pub': bytes.fromhex(data['server_session_pub']),
            'server_dilithium_pub_key': bytes.fromhex(data['server_dilithium_pub_key'])
        }

        elif 'ciphertext' in data:
        # This formats the package from the client for the server
            keys = {
            'client_ciphertext': bytes.fromhex(data['ciphertext']),
            'client_dilithium_pub_key': bytes.fromhex(data['client_dilithium_pub_key'])
        }

        else:
            raise ValueError("Received unknown key format in key_recv")

        return keys 
    
