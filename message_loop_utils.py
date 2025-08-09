import json
import aes_encrpyt
import key_handler 
from datetime import datetime
#recv format
def recv_format(socket):
    msg_prefix = socket.recv(4)
    if not msg_prefix or len(msg_prefix) < 4:
        return b''
    print(f"[DEBUG] Waiting for message, got prefix: {msg_prefix}")
    total_bytes = int.from_bytes(msg_prefix, 'big')
    if total_bytes <= 0:
        return b''
    print(f"[DEBUG] Expecting {total_bytes} bytes...")
    json_data = b''
    while len(json_data) < total_bytes:
        packet = socket.recv(total_bytes - len(json_data))
        if not packet:
            return b''
        json_data += packet
        print(f"[DEBUG] Received chunk: {len(packet)} bytes, total so far: {len(json_data)} bytes")
        
    print(f"[DEBUG] Finished receiving message. Total bytes: {len(json_data)}")
    try:
        
        return json.loads(json_data.decode())
    except json.JSONDecodeError:
        print("[-] JSON decode failed. Raw data:", json_data)
        return b''

#send format 
def send_format(socket , data):
    json_string = json.dumps(data)#creates a json format for data 
    #Grabs json length
    length = len(json_string.encode())  
    #converts int to binary rep so that it can be sent to the client 
    msg_lenth  = length.to_bytes(4,'big')
    #Sending how long the msg will be to the client so that when sending the json file it knows when to stop. Based on what I implmented on client end
    socket.send(msg_lenth)#sends header
    socket.send(json_string.encode())#sends data 
    
    #this function automates encrypting and signing messages to be sent 
def send_encrypted_message (socket,d_key,shared_secret,plaintext):
        plaintext = json.dumps(plaintext)
        ciphertext , iv = aes_encrpyt.encrypt(plaintext.encode(),shared_secret)
        #The payload stores the ciphertext and iv 
        payload = {

            'ciphertext' : ciphertext.hex(),
            'iv' : iv.hex()
        }
        #this signs the serialized data  
        
        signature = key_handler.message_signing(d_key, json.dumps(payload, sort_keys=True).encode())
       
        package = {
            'payload': payload,
            'sig' : signature.hex()

        }
        print(f'encrypted data send: {ciphertext} (for demo) | Dilithum Signiture for payload: {signature}\n')
        send_format(socket,package)

def recv_encrypted_message(socket,d_key,shared_secret):
    
    data = recv_format(socket)
    if data == b'':  # connection closed or bad data
        return b''

    # Verify signature
    is_valid = key_handler.message_verfication(
        json.dumps(data['payload'], sort_keys=True).encode(),
        bytes.fromhex(data['sig']),
        d_key
    )
    if not is_valid:
        raise ValueError('Signature Verification Failed')

    # Decrypt message
    plaintext = aes_encrpyt.decrypt(
        bytes.fromhex(data['payload']['ciphertext']),
        shared_secret,
        bytes.fromhex(data['payload']['iv'])
    )

    return json.loads(plaintext)



#Only used for intial key exchange
# key_sends formats the data correctly to be sent to either client or server 
def key_send(socket,dilithium_keys,key):
        

        if isinstance(key,dict) and 'session_pub' in key:
            #Stores kyber and dilithium pub keys from server to send to client
            payload = {
                'type' : "server_keys",
                'server_session_pub': key['session_pub'].hex(),
            }
        elif isinstance(key,bytes):
            payload = {
                'type' : "client_keys",
                'ciphertext' : key.hex() ,
        
             }
            #stores what the client would generate to send to server
        else:
             raise ValueError('Invalid Key format to key_send()')
        print(f'keys sent: {payload} (demo only)\n')

        signature = key_handler.message_signing(dilithium_keys['dilithium_priv_key'], json.dumps(payload, sort_keys=True).encode())

        package = {
             
            'payload' : payload,
            'dilithium_pub_key': dilithium_keys['dilithium_pub_key'].hex(),
            'dilithium_expiration' : dilithium_keys['expires'].isoformat(),
            'sig' : signature.hex()
        }

        #Send to client or server
        print('keys sent')
        send_format(socket,package)
        
#recvs data and formats its from hex to bytes and stores it checks if it comes from client or server ( might be able to delete seems useless)
def key_recv(socket):
        #returns the correctly formmated data from client 
        data = recv_format(socket)
    



        is_valid = key_handler.message_verfication(json.dumps(data['payload'], sort_keys=True).encode(),bytes.fromhex(data['sig']),bytes.fromhex(data['dilithium_pub_key']))
        if is_valid is not True:
            raise ValueError('Signiture Verfication Failed')

        #checks if it is coming from server 
        if  data['payload']['type'] == 'server_keys':
        # This formats the package from the server for the client
            keys = {
            'server_session_pub': bytes.fromhex(data['payload']['server_session_pub']),
            'server_dilithium_pub_key': bytes.fromhex(data['dilithium_pub_key'])
        }

        elif  data['payload']['type'] == 'client_keys':
        # This formats the package from the client for the server
            keys = {
            'client_ciphertext': bytes.fromhex(data['payload']['ciphertext']),
            'client_dilithium_pub_key': bytes.fromhex(data['dilithium_pub_key']),
            'client_dilithium_expiration' : datetime.fromisoformat(data['dilithium_expiration'])
        }

        else:
            raise ValueError("Received unknown key format in key_recv")
        print(f'keys recv: {keys} (demo only)\n')
        return keys 