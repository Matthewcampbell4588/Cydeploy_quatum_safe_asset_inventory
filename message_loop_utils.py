import json
import aes_encrpyt
import key_handler

#recv format
def recv_format(client_socket):
    msg_prefix = client_socket.recv(4)#recieves 4 byte header for message length
    total_bytes = int.from_bytes(msg_prefix) #converts it to a int
    remaining_bytes = total_bytes #initlize for loop stores total and subtracts based off data recv
    json_data = b''#stores it in binary

    #recv loop were it adds each packet of data to the json_data varaible, then using that packet length subtracts it from total length left
    while remaining_bytes > 0:
        packet = client_socket.recv(remaining_bytes)#each data packet
        json_data += packet#data packet being stored in binary format
        remaining_bytes = remaining_bytes - len(packet)#checks how much of the data is left based on the 4 byte header
    data = json.loads(json_data.decode())#loads the json to a dic
    return data

#send format 
def send_format(client_socket , data):
    json_string = json.dumps(data)#creates a json format for data 
    #Grabs json length
    length = len(json_string.encode())  
    #converts int to binary rep so that it can be sent to the client 
    msg_lenth  = length.to_bytes(4,'big')
    #Sending how long the msg will be to the client so that when sending the json file it knows when to stop. Based on what I implmented on client end
    client_socket.send(msg_lenth)#sends header
    client_socket.send(json_string.encode())#sends data 
    
    #this function automates encrypting and signing messages to be sent 
def send_encrypted_message (client_socket,d_key,shared_secret,plaintext):
        ciphertext , iv = aes_encrpyt.encrypt(plaintext,shared_secret)
        #The payload stores the ciphertext and iv 
        payload = {

            'ciphertext' : ciphertext.hex(),
            'iv' : iv.hex()
        }
        #this signs the serialized data  
        signature = key_handler.message_signing(d_key, json.dumps(payload).encode())

        package = {
            'payload': payload,
            'sig' : signature

        }

        send_format(client_socket,package)

def recv_encrypted_message(client_socket,d_key,shared_secret):
        try:
            data = recv_format(client_socket)
            is_valid = key_handler.message_verfication(bytes.fromhex(data['payload']),bytes.fromhex(data['sig']),d_key)
            if is_valid is not True:
                raise ValueError('Signiture Verfication Failed')
            else:
                plaintext  = aes_encrpyt.decrypt(bytes.fromhex(data['payload']['ciphertext']),shared_secret)
                return plaintext
        except Exception as e:
            print(f'[ERROR] {e}')



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
        send_format(client_socket,package)
        
#recvs data and formats its from hex to bytes and stores it checks if it comes from client or server
def key_recv(client_socket):
        #returns the correctly formmated data from client 
        data = recv_format(client_socket)

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