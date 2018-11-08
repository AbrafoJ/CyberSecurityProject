#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sun Oct  7 09:55:21 2018

@author: flo
"""
import os, const
from   cryptography.hazmat.primitives.asymmetric import rsa
from   cryptography.hazmat.primitives.asymmetric import padding as rsa_pad
from   cryptography.hazmat.primitives.ciphers    import Cipher, algorithms, modes
from   cryptography.hazmat.primitives            import padding, hashes, hmac, serialization
from   cryptography.hazmat.backends              import default_backend


def my_encrypt_hmac(message, enc_key, hmac_key):
    if(len(enc_key) < const.KEY_LENGTH):
        print("Error: Key must be 128 bytes")
        return -1
    
    #pad message
    padder     = padding.PKCS7(const.BLOCK_SIZE).padder()
    padded_msg = padder.update(message) + padder.finalize()
    
    #generate IV
    IV = os.urandom(const.IV_LENGTH)            
    
    #create cipher with key + IV
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(padded_msg) + encryptor.finalize()
    
    #create tag
    hmac_tag = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend()) 
    hmac_tag.update(cipher_text) #hashes the cipher_text                        # M ( Ko || M ) ( Ki || M )
    
    return cipher_text, IV, hmac_tag.finalize()
    
def my_decrypt_hmac(cipher_text, IV, enc_key, hmac_key, hmac_tag):
    decrypt_tag = hmac.HMAC(hmac_key, hashes.SHA256(), backend=default_backend())
    decrypt_tag.update(cipher_text)
    
    #check if cipher is good
    decrypt_tag.verify(hmac_tag)
    
    #create cipher with key + IV
    cipher = Cipher(algorithms.AES(enc_key), modes.CBC(IV), backend=default_backend())
    decryptor = cipher.decryptor()
    cipher_text = decryptor.update(cipher_text) + decryptor.finalize()
    
    #unpad
    unpadder = padding.PKCS7(const.BLOCK_SIZE).unpadder()
    plain_text = unpadder.update(cipher_text) + unpadder.finalize() 

    return plain_text

def file_encrypt_hmac(filepath):
    file_name = os.path.basename(filepath)
    name,ext = os.path.splitext(file_name)
    enc_key  = os.urandom(const.KEY_LENGTH) 
    hmac_key = os.urandom(const.KEY_LENGTH) 
    
    try:
        file = open(file_name, "rb") #read bytes
        jpeg_file = file.read()
    finally:
        file.close()

    jpeg_cipher_text, IV, tag = my_encrypt_hmac(jpeg_file,enc_key,hmac_key)
    
    try:
        jpeg_enc = open("enc.txt", "wb") #write bytes
        jpeg_enc.write(jpeg_cipher_text)
    finally:
        jpeg_enc.close()

    return jpeg_cipher_text, IV, tag, enc_key, hmac_key, ext.encode()

def file_decrypt_hmac(filepath, IV, enc_key, hmac_key, tag):
    file_name = os.path.basename(filepath)
    name,ext = os.path.splitext(file_name)

    try:
        file = open(file_name, "rb")                          
        enc = file.read()
    finally:
        file.close()
        
    M = my_decrypt_hmac(enc, IV, enc_key, hmac_key, tag)
    
    try:
        dec = open("dec.txt", "wb") 
        dec.write(M)           
    finally:
        dec.close()
    
    return M


def generate_keys(filepath):
    pem_count = 0
    
    for file in os.listdir(filepath):
        if file.endswith(".pem"):
            pem_count += 1
            
            pem_file = open(file, "r")
            header = pem_file.read()
            pem_file.close()
            
            if "-----BEGIN RSA PRIVATE KEY-----" in header:
                private_pem = filepath + file #concat path and filename
                print(private_pem)
            elif "-----BEGIN PUBLIC KEY-----" in header:
                public_pem = filepath + file
                print(public_pem)
                
    if pem_count is 0:
        print("does not exist")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
        #highest known prime, largest fermat number, large enough to avoid attacks to which RSA is vulnerable within small exponents
        public_key = private_key.public_key()
        
        with open(filepath+"private.pem", 'wb') as priv_pem_file:
            priv_pem_file.write(private_key.private_bytes( encoding=serialization.Encoding.PEM, 
                                                            format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                            encryption_algorithm = serialization.NoEncryption()))
        
        with open(filepath+"public.pem", 'wb') as pub_pem_file:
            pub_pem_file.write(public_key.public_bytes( encoding=serialization.Encoding.PEM,
                                                        format=serialization.PublicFormat.SubjectPublicKeyInfo))

    return private_pem, public_pem

def my_RSA_encrypt(filepath, rsa_publickey_filepath):
    C, IV, tag, enc_key, hmac_key, ext = file_encrypt_hmac(filepath)

    with open(rsa_publickey_filepath, 'rb') as pub_pem_file:
        public_key = serialization.load_pem_public_key(pub_pem_file.read(),
                                                       backend=default_backend())
        
    rsa_cipher = public_key.encrypt(enc_key+hmac_key,
                                    rsa_pad.OAEP(mgf=rsa_pad.MGF1(algorithm=hashes.SHA256()), 
                                                 algorithm=hashes.SHA256(), 
                                                 label=None))
    return rsa_cipher, C, IV, tag, ext

def my_RSA_decrypt(filepath, rsa_cipher, C, IV, hmac_tag, ext, rsa_privatekey_filepath):
    with open(rsa_privatekey_filepath, 'rb') as priv_pem_file:
        private_key = serialization.load_pem_private_key(priv_pem_file.read(),
                                                         password=None,
                                                         backend=default_backend())
        
    dec_keys = private_key.decrypt(rsa_cipher, rsa_pad.OAEP(mgf=rsa_pad.MGF1(algorithm=hashes.SHA256()),
                                                            algorithm=hashes.SHA256(),
                                                            label=None))
    dec_enc_key = dec_keys[:const.KEY_LENGTH]
    dec_hmac_key = dec_keys[const.KEY_LENGTH:]
    
    M = file_decrypt_hmac(filepath, IV, dec_enc_key, dec_hmac_key, hmac_tag)
    
    return M

public_key_path = "/Users/flo/.spyder-py3/378_FileEnc/378_FileEnc/public.pem"
private_key_path = "/Users/flo/.spyder-py3/378_FileEnc/378_FileEnc/private.pem"

plaintext_filepath = "/Users/flo/.spyder-py3/378_FileEnc/378_FileEnc/message.txt"
ciphertext_filepath = "/Users/flo/.spyder-py3/378_FileEnc/378_FileEnc/enc.txt"

rsa_cipher, C, IV, tag, ext = my_RSA_encrypt(plaintext_filepath, public_key_path)
M                           = my_RSA_decrypt(ciphertext_filepath, rsa_cipher, C, IV, tag, ext, private_key_path)