from cryptography.fernet import Fernet
#Fernet is using AES-128 with CBC mode  for encrypting data 
import time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.asymmetric import padding  
from cryptography.hazmat.primitives import hashes  


#in This module we will handle session keys, signing, and verifying messages

 
'''
THIS PART WAS FOR MAKING RSA PUBLIC AND PRIVATE KEYS AND SAVE THEM ON SYSTEM 

#here we generate the public key and private key for 
private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
public_key = private_key.public_key()

# Save the private key in PEM format encrypted
with open("rsapv_client.pem", "wb") as f:  
    f.write(private_key.private_bytes(  
        encoding=serialization.Encoding.PEM,  
        format=serialization.PrivateFormat.TraditionalOpenSSL,  
        encryption_algorithm=serialization.BestAvailableEncryption(b"12345"),  
    )  
)  
  
# Save the Public key in PEM format  
with open("rsapub_client.pem", "wb") as f:  
    f.write(public_key.public_bytes(  
        encoding=serialization.Encoding.PEM,  
        format=serialization.PublicFormat.SubjectPublicKeyInfo,  
    )  
)
'''
def save_time(time):
    f = open("time.txt", "w+")
    f.seek(0)
    f.write(str(time))
    f.close

def load_time():
    f = open("time.txt", "r")
    current_time = float(f.read())
    print(current_time)
    return current_time

def check_time():
    #This function returns time any time we call it in Seconds
    ts = time.time()
    return ts 


def key_is_expired(expiration_time):
    #we use this method to check if the key is valid yed or not we have to generate new session key
    now = check_time()
    old = load_time()
    if now - old > expiration_time:
        print("key is expired")
        return True
    else:
        print("key is valid yet")
        return False

def generate_session_key():
    #this funciton returns the session key and the creation time of that key# 
    key = Fernet.generate_key()
    ts = time.time()
    print("what the fuck is going on")
    older_key_time = load_time()
    save_time(ts)
    return key

def encrypt_session_key(session_key, public_key):
    #this method will encrypt the session key with pair's public key
    ciphered_session_key = public_key.encrypt(  
    session_key,  
    padding.OAEP(  
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  
            algorithm=hashes.SHA256(),  
            label=None  
        )  
    ) 
    return ciphered_session_key

def decrypt_session_key(ciphered_session_key, private_key):
    #This method will decrypt ciphered_session_key that is sent from out pair
    session_key = private_key.decrypt(  
    ciphered_session_key,  
    padding.OAEP(  
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  
            algorithm=hashes.SHA256(),  
            label=None  
        )  
    )  
    return session_key 


def encrypt_message(plaintext, session_key):
 #this method encrypt messages with AES algorithm in CBC mode with passed key 
    e = Fernet(session_key)
    ciphertext = e.encrypt(plaintext)
    return ciphertext

def decrypt_message(ciphertext, session_key):
    #In this method we decrypt message with given session key
    d = Fernet(session_key)
    plaintext = d.decrypt(ciphertext)
    return plaintext

def sign_message(message, private_key):
    #In this method we will make a sign with rsa private key and sha256 hash function
    sig = private_key.sign(  
    message,  
    padding.PSS(  
        mgf=padding.MGF1(algorithm=hashes.SHA256()),  
        salt_length=padding.PSS.MAX_LENGTH,  
    ),  
    hashes.SHA256()  
    )
    return sig

def signature_is_valid(message, signature, public_key):
    #this method will verify the message that is valid or not 
    try:
        validation = public_key.verify(  
            signature,  
            message,  
            padding.PSS(  
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),  
                    salt_length=padding.PSS.MAX_LENGTH,  
            ),  
            hashes.SHA256()  
        ) 
    except :
        print("the message is modified in the way, calling client to send it again")
        return False
    else : 
        print("message is valid")
        return True


# 



# print(my_key, time, older_time)




