import socket 
from datetime import datetime
import secure_connection
from cryptography.hazmat.backends import default_backend  
from cryptography.hazmat.primitives.asymmetric import padding  
from cryptography.hazmat.primitives import hashes  
from cryptography.hazmat.primitives.serialization import load_pem_private_key  
from cryptography.hazmat.primitives.serialization import load_pem_public_key  

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 4004     # Port to listen on (non-privileged ports are > 1023)

#here we get server private key and client public key
serverPvKey = load_pem_private_key(open('rsakey.pem', 'rb').read(),b"12345",default_backend())  
clientPubKey = load_pem_public_key(open('rsapub_client.pem', 'rb').read(),default_backend())

# s_key = b""
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    session_key = b""
    with conn:
        print('Connected by', addr)
        data = conn.recv(1024)
        #If the client wants to send new session key we accept it
        if data == b"NEW_KEY":
            ciphered_session_key = conn.recv(1024)
            print("ciphered_session_key received and = :", ciphered_session_key)
            session_key = secure_connection.decrypt_session_key(ciphered_session_key, serverPvKey)
        if data == b"FILE":
            pass
        if data == b"TEXT":
            print(data)
        # s_key += data
        # f.write(data)
        # counter = 1
        print("new dataaaaaaaaaaa")
        while (data):
            
            # print(data)
            
            
            data = conn.recv(1024)
            print("data recieved")
            if data == b"NEW_KEY":
                ciphered_session_key = conn.recv(1024)
                print("ciphered_session_key received and = :", ciphered_session_key)
                session_key = secure_connection.decrypt_session_key(ciphered_session_key, serverPvKey)
                print("New session key received")


            #Receiving FILE
            if data == b"FILE":

                if data == b"NEW_KEY":
                    ciphered_session_key = conn.recv(1024)
                    print("ciphered_session_key received and = :", ciphered_session_key)
                    session_key = secure_connection.decrypt_session_key(ciphered_session_key, serverPvKey)
                    print("New session key received")

                print("im in file reciever")
                f = open("server_file.pdf", "wb")
                ciphered_file = conn.recv(1024)
                
                while (ciphered_file):
                    check = conn.recv(1024)
                    print(check)
                    if check == b"FINISH":
                        break
                    else:
                        ciphered_file += check
                    # print("saalam")
                print(ciphered_file)
                deciphered_file = secure_connection.decrypt_message(ciphered_file, session_key)
                signature = conn.recv(2048)
                if secure_connection.signature_is_valid(deciphered_file, signature, clientPubKey):
                    print("File is valid")
                    f.write(deciphered_file)
                else:
                    print("File is invalid")


            #Receiving TEXT
            if data == b"TEXT":
                print("Recieving text")
                data = conn.recv(1024)

                ciphered_text = data
                while (data):
                    data = conn.recv(1024)
                    if data == b"EOT":
                        break
                    ciphered_text += data

                plain_text = secure_connection.decrypt_message(ciphered_text, session_key)
                print("The text sent from client is:\n",plain_text.decode())
                print("Recieving signature")
                signature = conn.recv(1024)
                if secure_connection.signature_is_valid(plain_text, signature, clientPubKey):
                    print("This message is valid")
                else:
                    print("This message is modified on the way please send it again")
            # print(data)
            # s_key += data
            # f.write(data)
            # counter +=1
        # d = serverPvKey.decrypt(s_key,  
        #                         padding.OAEP(  
        #     mgf=padding.MGF1(algorithm=hashes.SHA256()),  
        #     algorithm=hashes.SHA256(),  
        #     label=None  
        #     )  
        # )
        # print(s_key)
        # print(d)
        # f.write(d)

        # print(counter)
        # f.close()
            # conn.sendall(data)

