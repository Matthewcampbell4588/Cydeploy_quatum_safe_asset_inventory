import key_handler
import time 
import threading
import message_loop_utils
from datetime import timedelta ,datetime,timezone

#need to set a time to sleep for an hour since the thread started. This will update kyber key and check dilithium key
#need a way to notify client for new key exchange 
#ensure keys are updated correctly

# Shared lock to prevent simultaneous refreshes
refresh_lock = threading.Lock()

def kyber_refresh_loop(connected_clients, clients_lock):
    while True:
        time.sleep(3600)  # Wait 1 hour between Kyber refreshes
        with refresh_lock:  # Prevent overlap with Dilithium refresh
            print("[+] Refreshing Kyber keys...")
            # Here you'd refresh per-session Kyber keys for each client
            with clients_lock:
                for client in connected_clients:
                    try:
                        if (client['client_pub'] - datetime.now(timezone.utc)) < timedelta(days=2):
                            refresh_payload = {
                                'type' :'dilithium_refresh_request'
                            }
                            message_loop_utils.send_encrypted_message(
                            client["sock"],
                            client["dilithium_priv_key"],  # Sign with Dilithium
                            client["shared_secret"],       # Encrypt with current session key
                            refresh_payload
                            )
                            time.sleep(5)
                        new_kyber = key_handler.kyber_key_gen()
                        refresh_payload = {
                            'type': 'kyber_refresh',
                            'kyber_pub_key': new_kyber['kyber_pub_key'].hex()
                        }
                        message_loop_utils.send_encrypted_message(
                            client["sock"],
                            client["dilithium_priv_key"],  # Sign with Dilithium
                            client["shared_secret"],       # Encrypt with current session key
                            refresh_payload
                        )
                        client["shared_secret"] = new_kyber['shared_secret']
                    
                        return new_kyber['kyber_priv_key']
                    except Exception as e:
                        print(f"[-] Failed to refresh Kyber for client: {e}")
            print("[+] Kyber keys refreshed.")



def server_dilithium_refresh(server_keys, connected_clients, clients_lock):
   
     while True:
        # Check every hour if expired
        if (server_keys['expires'] - datetime.now(timezone.utc)) < timedelta(days=2): #refreshes keys 2 days prior to keys expiration
            print("[+] Refreshing Dilithium keys...")
            new_keys = key_handler.dilithium_key_gen()

            refresh_payload = {
                'type': 'dilithium_refresh',
                'server_dilithium_pub_key': new_keys['dilithium_pub_key'].hex(),
                'dilithium_expiration': new_keys['expires'].isoformat()
            }

            with clients_lock:
                for client in connected_clients:
                    try:
                        message_loop_utils.send_encrypted_message(
                            client["sock"],
                            server_keys['dilithium_priv_key'],  # sign with old key
                            client["shared_secret"],            # encrypt with client's session key
                            refresh_payload
                        )
                    except Exception as e:
                        print(f"[-] Failed to send refresh to client: {e}")
       
                server_keys.clear()#clears dic for server
                server_keys.update(new_keys)#adds the new generated dilithium keys to server
            

            print("[+] Dilithium keys updated:", server_keys)
            
        time.sleep(86400)
