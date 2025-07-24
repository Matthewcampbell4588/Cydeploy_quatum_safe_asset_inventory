import oqs
from datetime import datetime, timezone, timedelta
import message_loop_utils

def message_signing(dilithium_private_key, msg):
    dilithium_priv = dilithium_private_key['dilithium_priv_key']
    return dilithium_priv.sign(msg)

def message_verification(msg, sig, dilithium_pub):
    with oqs.Signature('Dilithium2') as verify:
        return verify.verify(msg, sig, dilithium_pub)

def dilithium_key_gen():
    diltium_kem = oqs.Signature('Dilithium2')
    dilithium_public_key = diltium_kem.generate_keypair()
    timestamp, created = key_time_stamp('dilithium')
    return {
        'dilithium_priv_key': diltium_kem,
        'dilithium_pub_key': dilithium_public_key,
        'created': created,
        'expires': timestamp
    }

def key_time_stamp(option):
    now = datetime.now(timezone.utc)
    if option == 'session':
        return now + timedelta(hours=1), now
    elif option == 'dilithium':
        return now + timedelta(days=30), now

def kyber_key_gen():
    kem = oqs.KeyEncapsulation('Kyber512')
    kyber_pub_key = kem.generate_keypair()
    return {
        'session_pub': kyber_pub_key,
        'session_priv': kem
    }

def kyber_encap_decap(key, ciphertext, option):
    if option == 'encap':
        with oqs.KeyEncapsulation('Kyber512') as kem_encap:
            return kem_encap.encap_secret(key)
    elif option == 'decap':
        shared_secret = key.decap_secret(ciphertext)
        key.free()
        return shared_secret
