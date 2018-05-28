
# https://github.com/bwesterb/py-seccure
import seccure
import binascii
import hashlib

default_curve_name = 'secp160r1'

def utf8_encode(to_enc):
    return to_enc.encode('utf-8')

def hex_encode(to_enc):
    if isinstance(to_enc,bytes):
        return '0x'+to_enc.hex()
    
    if isinstance(to_enc,str):
        return '0x'+utf8_encode(to_enc).hex()
    
    if isinstance(to_enc,seccure.PubKey):
        return hex_encode(to_enc.to_bytes())
    
    raise Exception(f"cant' hex encode unrecognized type {type(to_enc)}")

def hex_decode(to_dec,dec_type=bytes):
    if dec_type is bytes:
        return binascii.unhexlify(to_dec[2:])
    
    if dec_type is seccure.PubKey:
        return default_curve.pubkey_from_string(hex_decode(to_dec))
    
    raise Exception(f"cant' hex decode hex to unrecognized type {dec_type}")

def combine_hex(to_enc1,to_enc2):
    return hex_encode(hex_decode(to_enc1)+hex_decode(to_enc2) )


def create_pubkey(passphrase):
    passphrase_bytes = utf8_encode(passphrase)
    pubkey_obj= seccure.passphrase_to_pubkey(passphrase_bytes,curve=default_curve_name)
    return hex_encode(pubkey_obj)


def sign(message,passphrase):
    passphrase_bytes = utf8_encode(passphrase)
    
    msg_bytes = utf8_encode(message)
    non_hex_sig =seccure.sign(msg_bytes, passphrase_bytes,sig_format=seccure.SER_BINARY)
    return hex_encode( non_hex_sig)


def verify(message,signature,public_key):
    msg_bytes = utf8_encode(message)
    sign_bytes = hex_decode(signature)
    pubkey_bytes = hex_decode(public_key)
    return seccure.verify(msg_bytes,sign_bytes,pubkey_bytes,curve=default_curve_name,sig_format=seccure.SER_BINARY,pk_format=seccure.SER_BINARY)


def crypto_hash(message,from_hex=True):
    if from_hex:
        return hex_encode(hashlib.sha512(hex_decode(message) ).digest())
    return hex_encode(hashlib.sha512(utf8_encode(message) ).digest())

