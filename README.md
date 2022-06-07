# Peer-to-peer Chatting
 P2P chatting application with python

 Muhammet Hasan Albayrak - 150117053
 Esraa Ismail Taha Turky - 150119529
# 1. Public Key Certification.
Each user should generate an RSA public-private key pair
once and register the server with her username and public key. Server signs this key
and creates a certificate using x509 library, stores the certificate and also sends a copy to the user. When
user receives the certificate, she verifies that the certificate is correct and the public
key is correctly received by the server.

Users create  public and private key pairs then when they  register to server, server signs their public key with it's 
private key and creates a certificate then sends the certificate back to user.

# 2. HandShaking 
One of the users sends a connection request to the server with the other user's name. The server create the connection and sends ip addresses to both of the sides.
The first user create TCP connection and sends Hello message to the other side a long with his certificate. user2 sends the certificate to the server to check it and wait for its response.
After getting the verification from the server user2 sends his certificate and nonce to user1 and user1 apply the same certificate check process.
After certificate check user1 encrypt the nonce with user2 public key and send it so user2 is the only one who can decrypt it and verify it and send ACK to user1.
After that user2 generate random string to use it as master secret and encrypt it and send it to user2.
By using master secret and nonce now user1 and user2 can create 2 keys for encryption. 

# 3 Key Generation
After nonce verifying is complete, each side generates a 32 bytes long AES key, a 16 bytes long IV and uses the nonce as salt.

# 4 Message Encryption
Before sending the message we encrypt the contents using AES in CBC mode and create a digest.
Then we send them both.

# 5 Message Integrity
We create a digest with every message and after receiving it we verify it using MAC key and SHA2.

# 6 Replay Attack
We keep a copy of every nonce, so when a duplicate arrives we know it is fake.

# security hols
one of the security hols in our app is that we are saving users certificates and keys unencrypted on our devises. Which mean that anyone can access it and use it.   

    

