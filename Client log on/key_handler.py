import oqs
from datetime import datetime,timezone,timedelta

def message_signing(dilithium_private_key, msg):
    return dilithium_private_key.sign(msg)

def message_verification(msg, sig, dilithium_pub):
    with oqs.Signature('Dilithium2') as verify:
        return verify.verify(msg, sig, dilithium_pub)

def dilithium_key_gen():
    dilithium_kem = oqs.Signature('Dilithium2')
    dilithium_public_key = dilithium_kem.generate_keypair()
    expires, created = key_time_stamp('dilithium')
    return {
        'dilithium_priv_key': dilithium_kem,
        'dilithium_pub_key': dilithium_public_key,
        'created': created,
        'expires': expires
    }

def key_time_stamp(option):
    now = datetime.now(timezone.utc)
    if option == 'session':
        return now + timedelta(hours=1), now
    elif option == 'dilithium':
        return now + timedelta(days=30), now

def kyber_key_gen():
    kem = oqs.KeyEncapsulation('Kyber512')
    pub = kem.generate_keypair()
    return {'session_pub': pub, 'session_priv': kem}

def kyber_encap_decap(key, ciphertext, option):
    if option == 'encap':
        with oqs.KeyEncapsulation('Kyber512') as kem:
            ct, secret = kem.encap_secret(key)
            return ct, secret
    elif option == 'decap':
        secret = key.decap_secret(ciphertext)
        key.free()
        return secret
