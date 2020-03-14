#!/usr/bin/python
"""
    server.py - host an SSL server that checks passwords

    CSCI 3403
    Authors: Matt Niemiec and Abigail Fernandes
    Number of lines of code in solution: 140
        (Feel free to use more or less, this
        is provided as a sanity check)

    Put your team members' names: Nimra Sharnez



"""

#we used https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html for help
import socket
import os
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random
from Crypto.PublicKey import RSA
import hashlib
import base64 as b
import uuid

host = "localhost"
port = 10001


# A helper function. It may come in handy when performing symmetric encryption
def pad_message(message):
    return message + " " * ((16 - len(message)) % 16)


# Write a function that decrypts a message using the server's private key
def decrypt_key(session_key):
    # TODO: Implement this function
    private_key = RSA.importKey(open("private.pem").read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    encryptedK = cipher_rsa.decrypt(session_key)

    return(encryptedK)


# Write a function that decrypts a message using the session key
def decrypt_message(client_message, session_key):
    # TODO: Implement this function

    key = session_key
    #print("here:", key)

    initialization_vector = client_message[:16]

    client_message = client_message[16:]

    cipher = AES.new(key, AES.MODE_CBC, initialization_vector)
    #initialization_vector 

    v = cipher.decrypt(client_message)
    
    #v = v.decode(); why does this not work
    
    return(v)


# Encrypt a message using the session key
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



# Receive 1024 bytes from the client
def receive_message(connection):
    return connection.recv(1024)


# Sends message to client
def send_message(connection, data):
    if not data:
        print("Can't send empty string")
        return
    if type(data) != bytes:
        data = data.encode()
    connection.sendall(data)


# A function that reads in the password file, salts and hashes the password, and
# checks the stored hash of the password to see if they are equal. It returns
# True if they are and False if they aren't. The delimiters are newlines and tabs
def verify_hash(user, password):
    try:

        reader = open("passfile.txt", 'r')

        for line in reader.read().split('\n'):
            line = line.split("\t")
            if line[0] == user:

                salt = line[1]
                #print(salt)

                hashed_password = hashlib.sha256(salt.encode() + password.encode()).hexdigest()
                

                return(line[2] == hashed_password)

        reader.close()
    except FileNotFoundError:
        return (False)
    return (False)


def main():
    #Set up network connection listener
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (host, port)
    print('starting up on {} port {}'.format(*server_address))
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(server_address)
    sock.listen(1)

    try:
        while True:
            # Wait for a connection
            print('waiting for a connection')
            connection, client_address = sock.accept()
            try:
                print('connection from', client_address)

                # Receive encrypted key from client
                encrypted_key = receive_message(connection)

                # Send okay back to client
                send_message(connection, "okay")

                # Decrypt key from client
                plaintext_key = decrypt_key(encrypted_key)
                
                # Receive encrypted message from client
                ciphertext_message = receive_message(connection)

                # TODO: Decrypt message from client
                dec = decrypt_message(ciphertext_message, plaintext_key)

                # TODO: Split response from user into the username and password
                dec = dec.split(' ')
                username = dec[0]
                print(username)
                password = dec[1]
                print(password)

                # TODO: Encrypt response to client
                if (verify_hash(username, password)):
                    m = encrypt_message("ok", plaintext_key)
                    print("Connected!")
                else:
                    m = encrypt_message("Cannot Connect", plaintext_key)
                    print("Failed to connect!")
                # Send encrypted response
                send_message(connection, m)

            finally:
                # Clean up the connection
                connection.close()
    finally:
        sock.close()

if __name__ in "__main__":
    main()
