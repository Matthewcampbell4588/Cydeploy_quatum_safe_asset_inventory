import message_loop_utils

def commands(type,d_key,shared_secret,socket):
    try:
        if type == 'video':
            print('video works')
            command_payload = {'type':'command',
                'command' : type}
            message_loop_utils.send_encrypted_message(socket,d_key,shared_secret,command_payload)
        elif type == 'message':
            print('message works')
            command_payload = {'type':'command',
                'command' : type}
            message_loop_utils.send_encrypted_message(socket,d_key,shared_secret,command_payload)
        elif type == 'rand num':
            print('random num works')
            command_payload = {'type':'command',
                'command' : type}
            message_loop_utils.send_encrypted_message(socket,d_key,shared_secret,command_payload)
        else:
            raise AssertionError('[-] ERROR: Not a Command Type.')
    except AssertionError as e:
        print(str(e))





