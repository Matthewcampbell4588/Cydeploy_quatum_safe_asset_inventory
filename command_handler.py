import message_loop_utils

def command_controller(data,d_key,shared_secret,socket):
    print(data)
    try:
        if 'command_req' in data:
            command_payload = {
                'type':'command_req',
                'command' : data['command_req']
                }
            message_loop_utils.send_encrypted_message(socket,d_key,shared_secret,command_payload)
            print('data sent!')
        elif data.get('type') == 'command_reponse':
            command_payload = {
                'type' : 'command_reponse',
                'action' : data['action'],
                'command' : data['command']
            }
            message_loop_utils.send_encrypted_message(socket,d_key,shared_secret,command_payload)
            print('data sent')
        else:
            raise AssertionError('[-] ERROR: Not a Command Type.')
    except AssertionError as e:
        print(str(e))




                
