import json


#recv format
def recv(client_socket):
    msg_prefix = client_socket.recv(4)#recieves 4 byte header for message length
    total_bytes = int.from_bytes(msg_prefix) #converts it to a int
    remaining_bytes = total_bytes #initlize for loop stores total and subtracts based off data recv
    json_data = b''#stores it in binary

    #recv loop were it adds each packet of data to the json_data varaible, then using that packet length subtracts it from total length left
    while remaining_bytes > 0:
        packet = client_socket.recv(remaining_bytes)
        json_data += packet
        remaining_bytes = remaining_bytes - len(packet)
    data = json.loads(json_data.decode())#loads the json to a dic
    return data

#send format 
def send(client_socket , data):
    json_string = json.dumps(data)#creates a json format for data 
    #Grabs json length
    length = len(json_string.encode())  
    #converts int to binary rep so that it can be sent to the client 
    msg_lenth  = length.to_bytes(4,'big')
    #Sending how long the msg will be to the client so that when sending the json file it knows when to stop. Based on what I implmented on client end
    client_socket.send(msg_lenth)#sends header
    client_socket.send(json_string.encode())#sends data 
    