import socket
from datetime import datetime
import secure_connection
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.asymmetric import padding  
from cryptography.hazmat.primitives import hashes  
from cryptography.hazmat.primitives.serialization import load_pem_private_key  
from cryptography.hazmat.primitives.serialization import load_pem_public_key  

#Get the server's public key and clients private key for authentication (Signeture) and sending session keys
serverPubKey = load_pem_public_key(open('rsapub.pem', 'rb').read(),default_backend()) 
clientPvKey = load_pem_private_key(open('rsapv_client.pem', 'rb').read(),b"12345",default_backend())

#Here we define some global variables for handling session keys time expiration 


HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 4004     # The port used by the server
expiration_time = 20 #Expiration time for session key in >>Seconds<<

# file = open('file1.pdf', 'rb')
# my_file = file.read() # The key will be type bytes
# file.close()
# print(my_file)



# print(ciphertext)
# alicePrivKey = load_pem_private_key(open('rsakey.pem', 'rb').read(),b"12345",default_backend())  

# d = alicePrivKey.decrypt(ciphertext,  
#                                 padding.OAEP(  
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),  
#             algorithm=hashes.SHA256(),  
#             label=None  
#             )  
# ) 
# print(d)
if __name__ == "__main__":
    session_key = b""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        if secure_connection.key_is_expired(expiration_time):
            session_key = secure_connection.generate_session_key()
            ciphered_session_key = secure_connection.encrypt_session_key(session_key, serverPubKey)
            s.sendall(b"NEW_KEY")
            s.sendall(ciphered_session_key)
        while True:
            my_req = input("0.Enter 0 for closing the connection\n1.Pleas enter 1 for sending text\n2.Enter 2 for sending file\n")
            if my_req == '0':
                s.close()
                break
            if my_req == '1':
                #First we check if the sessoin_key is expired
                #if its not we use the old session key else we 
                #update the session key and send it to server too in cipher mode
                if secure_connection.key_is_expired(expiration_time):
                    session_key = secure_connection.generate_session_key()
                    ciphered_session_key = secure_connection.encrypt_session_key(session_key, serverPubKey)
                    s.sendall(b"NEW_KEY")
                    s.sendall(ciphered_session_key)
                #Here we tell the server tha we are sending a text     
                
                print("Please Enter your text:\n")
                text = input()
                s.sendall(b"TEXT")
                text = text.encode()
                ciphered_text = secure_connection.encrypt_message(text, session_key)
                s.sendall(ciphered_text)
                s.sendall(b"EOT")
                #We sign the message here
                signature = secure_connection.sign_message(text, clientPvKey)
                s.sendall(signature)

            if my_req == '2':
                if secure_connection.key_is_expired(expiration_time):
                    session_key = secure_connection.generate_session_key()
                    ciphered_session_key = secure_connection.encrypt_session_key(session_key, serverPubKey)
                    s.sendall(b"NEW_KEY")
                    s.sendall(ciphered_session_key)

                s.sendall(b"FILE")
                print("Please enter the file name:\n")
                file_name = input()
                file = open(file_name, 'rb')
                my_file = file.read() # The key will be type bytes
                file.close()
        
                ciphered_file = secure_connection.encrypt_message(my_file, session_key)
                #We sign the message here
                signature = secure_connection.sign_message(my_file, clientPvKey)
                s.sendall(ciphered_file)
                print("File sent from client")
                finish = input("please write FINISH\n")
                s.sendall(finish.encode())
                s.sendall(signature)

                

            
        # s.sendall(ciphertext) 

    # data = s.recv(1024)
    # print('Received', repr(data))
