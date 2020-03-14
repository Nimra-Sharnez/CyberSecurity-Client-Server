#!/usr/bin/python
"""
    client.py - Connect to an SSL server

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 117
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names: Nimra Sharnez



"""

import socket
import os
from os import urandom
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
from Crypto.PublicKey import RSA

host = "localhost"
port = 10001


# A helper function that you may find useful for AES encryption
# Is this the best way to pad a message?!?!
def pad_message(message):
    return message + " "*((16-len(message))%16)

# TODO: Generate a cryptographically random AES key
def generate_key():
    # TODO: Implement this function
    
    AESkey = os.urandom(16)
    

    return(AESkey)



# Takes an AES session key and encrypts it using the appropriate
# key and return the value
def encrypt_handshake(session_key):
    # TODO: Implement this function
    


    recipient_key = RSA.importKey(open("receiver.pem").read())
    
    
    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    encrypted = cipher_rsa.encrypt(session_key)

    return(encrypted)




# Encrypts the message using AES. Same as server function
def encrypt_message(message, session_key):
    # TODO: Implement this function
    
    key = session_key
    message = pad_message(message) #have to pad the message to make it x bytes
    message = message.encode()

    initialization_vector = Random.new().read(AES.block_size)
    #print("IV:", initialization_vector)

    cipher = AES.new(key, AES.MODE_CBC, initialization_vector)
    
    v = initialization_vector + cipher.encrypt((message))
    
    
    return(v)
 



# Decrypts the message using AES. Same as server function
def decrypt_message(message, session_key):
    # TODO: Implement this function

    key = session_key
    #print("here:", key)

    initialization_vector = message[:16]

    client_message = message[16:]

    cipher = AES.new(key, AES.MODE_CBC, initialization_vector)
    #initialization_vector 

    v = cipher.decrypt(client_message)
    
    #v = v.decode(); why does this not work
    
    return(v)



# Sends a message over TCP
def send_message(sock, message):
    sock.sendall(message)


# Receive a message from TCP
def receive_message(sock):
    data = sock.recv(1024)
    return data


def main():
    user = raw_input("What's your username? ")
    password = raw_input("What's your password? ")


    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the port where the server is listening
    server_address = (host, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)

    try:
        # Message that we need to send
        message = user + ' ' + password

        # Generate random AES key
        key = generate_key()

        # Encrypt the session key using server's public key
        encrypted_key = encrypt_handshake(key)

        # Initiate handshake
        send_message(sock, encrypted_key)

        # Listen for okay from server (why is this necessary?)
        if receive_message(sock).decode() != "okay":
            print("Couldn't connect to server")
            exit(0)
        else:
            print("Continue")

        # TODO: Encrypt message and send to server
        message2 = encrypt_message(message, key)

        send_message(sock, message2)

        # TODO: Receive and decrypt response from server
        m = receive_message(sock)
        final = decrypt_message(m , key)
        print(final)

        
        
    finally:
        print('closing socket')
        sock.close()




if __name__ in "__main__":
    main()
