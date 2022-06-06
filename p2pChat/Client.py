import base64
import threading
from hashlib import scrypt
from threading import Thread
from tkinter import *
import socket
import json
import logging
import colorama
import os
import uuid
from Crypto.Protocol.KDF import scrypt
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key

from CustomFormatter import CustomFormatter
# from security import decrypt_msg, encrypt_msg, generateRSAKeys, set_var, Key
from security import Key

colorama.init()

LOG_PATH = 'p2pChat/logs'
LOG_FILE_NAME = 'client'
logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
LOGGER = logging.getLogger("CLIENT")

fileHandler = logging.FileHandler("logs/client.log")
fileHandler.setFormatter(logFormatter)
LOGGER.addHandler(fileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
LOGGER.addHandler(consoleHandler)
LOGGER.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

ch.setFormatter(CustomFormatter())
LOGGER.addHandler(ch)
#


class Client(Thread):
    def __init__(self):
        super().__init__()
        self.ip = "127.0.0.1"
        self.port = 20001
        self.bufferSize = 1024
        self.serverUDP = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.pass_phrase = "SECURITY_HW_1"
        self.Key = Key()


    def gettingRSAKeys(self, username):
        pass_phrase = "SECURITY_HW_1".encode()
        if self.findFile(f"K{username}+.pem"):
            encoded_key = open(f"K{username}+.pem", "rb").read()
            ka_public = load_pem_public_key(encoded_key)
            encoded_key = open(f"K{username}-.pem", "rb").read()
            ka_private = load_pem_private_key(encoded_key, password=pass_phrase)
        else:
            self.Key.generateRSAKeys(username)
            encoded_key = open(f"K{username}+.pem", "rb").read()
            ka_public = load_pem_public_key(encoded_key)
            encoded_key = open(f"K{username}-.pem", "rb").read()
            ka_private = load_pem_private_key(encoded_key, password=pass_phrase)
        while True:
            # send public key to server
            self.serverTCP.send((ka_public.public_bytes(encoding=serialization.Encoding.PEM,
                                                        format=serialization.PublicFormat.SubjectPublicKeyInfo)))
            # get certificate from the server
            x = self.serverTCP.recv(self.bufferSize)
            certificate = x509.load_pem_x509_certificate(x)
            # TODO add certificate check here
            test = certificate.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                         format=serialization.PublicFormat.SubjectPublicKeyInfo) == ka_public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo)

            if (test):
                self.serverTCP.send(bytes('pass', 'utf-8'))
                self.certificate = certificate
                break
            else:
                self.serverTCP.send(bytes('wrong', 'utf-8'))

    def createMessagesfile(self, name):
        file = open(name + '.txt', 'a')
        return file

    def saveMessages(self, name, message):
        file = open(name + '.txt', 'a')
        file.write(message + '\n')
        file.close()

    def TCPConnection(self):
        # creating the TCP socket
        self.serverTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverTCP.connect((self.ip, 1234))
        print(self.serverTCP.recv(self.bufferSize).decode('utf-8'))

    def getType(self, type):
        self.serverTCP.send(bytes(type, 'utf-8'))

    def sendLogInData(self, username, password):
        self.serverTCP.send(bytes(username, 'utf-8'))
        self.serverTCP.send(bytes(password, 'utf-8'))
        respond = self.serverTCP.recv(self.bufferSize).decode('utf-8')
        return respond

    def waitForUsers(self):
        self.serverTCP.send(bytes('check', 'utf-8'))
        msgFromServer = self.serverTCP.recv(self.bufferSize).decode('utf-8')
        return msgFromServer

    def searchOrWait(self, check):
        self.serverTCP.send(bytes(check, 'utf-8'))

    # def sendCertificate(self):
    #     self.serverTCP.send(self.certificate.public_bytes(serialization.Encoding.PEM))
    #     self.serverTCP.

    def search(self, name):
        self.serverTCP.send(bytes(name, 'utf-8'))
        msgFromServer = self.serverTCP.recv(self.bufferSize)
        msgFromServer = json.loads(msgFromServer.decode())
        return msgFromServer

    def wait(self):
        msgFromServer = self.serverTCP.recv(self.bufferSize)
        msgFromServer = json.loads(msgFromServer.decode())
        return msgFromServer

    def createChatConnection(self, address):
        clientTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientTCP.bind((address[0], address[1]))

        clientTCP.listen(1)
        self.client, address = clientTCP.accept()
        # client.send(bytes('welcome', 'utf-8'))

    def connectToChat(self, address):
        self.reciverTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.reciverTCP.connect((address[0], address[1]))

    def chatR(self, name1, name2):
        while True:
            received_msg = self.reciverTCP.recv(self.bufferSize)
            digest = self.reciverTCP.recv(self.bufferSize)
            msg = self.Key.decrypt_msg(digest=digest, encrypted_data=received_msg)
            m = name1 + ': ' + msg.decode()
            if m == 'LOGOUT':
                print(m)
                return 'LOGOUT'
            else:
                print(m)
            mesge = input(name2 + ': ')
            if mesge == 'LOGOUT':
                self.reciverTCP.send(bytes(mesge, 'utf-8'))
                self.reciverTCP.close()
                self.serverTCP.send(bytes('LOGOUT', 'utf-8'))
                self.serverTCP.recv(self.bufferSize)
                break
            else:
                self.reciverTCP.send(bytes(mesge, 'utf-8'))

    def chatS(self, name1, name2):
        while True:
            mesge = input(name1 + ': ')
            self.saveMessages(name1 + '_' + name2, name1 + ': ' + mesge)
            if mesge == 'LOGOUT':
                self.client.send(bytes(mesge, 'utf-8'))
                self.client.close()
                self.serverTCP.send(bytes('LOGOUT', 'utf-8'))
                self.serverTCP.recv(self.bufferSize)
                break
            else:
                data, digest = self.Key.encrypt_msg(mesge)
                self.client.send(data)
                self.client.send(bytes(digest,'utf-8'))
            m = name2 + ': ' + self.client.recv(self.bufferSize).decode()
            self.saveMessages(name1 + '_' + name2, m)
            if m == 'LOGOUT':
                print(m)
                return 'LOGOUT'
            else:
                print(m)

    def findFile(self, file):
        return os.path.isfile(file) and os.path.getsize(file) > 0

    def handShakingServer(self, name1, name2):
        self.client.send(bytes('hello', 'utf-8'))
        self.client.send(self.certificate.public_bytes(serialization.Encoding.PEM))
        nonce = self.client.recv(self.bufferSize)
        LOGGER.info(f'nonce is {nonce}')
        userCertificate = x509.load_pem_x509_certificate(self.client.recv(self.bufferSize))
        LOGGER.info(f'receive certificate is {userCertificate}')
        while True:
            self.serverTCP.send(bytes('Certificate', 'utf-8'))
            self.serverTCP.send(userCertificate.public_bytes(serialization.Encoding.PEM))
            check = self.serverTCP.recv(self.bufferSize)
            if check.decode() == 'pass':
                print('certificate check done for both sides')
                userPublicKey = userCertificate.public_key()
                LOGGER.info('done with sender')
                # send the nonce again
                encreptedNonce = userPublicKey.encrypt(nonce,
                            padding.OAEP(
                                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                algorithm=hashes.SHA256(),
                                label=None
                            ))

                self.client.send(encreptedNonce)
                ack = self.client.recv(self.bufferSize).decode()
                LOGGER.info(f'ACK is {ack}')
                if ack == 'true':
                    masterSecret = uuid.uuid4().hex
                    encreptedMastersSecret = userPublicKey.encrypt(bytes(masterSecret,'utf-8'),
                                                           padding.OAEP(
                                                               mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                               algorithm=hashes.SHA256(),
                                                               label=None
                                                           ))
                    LOGGER.info(f'master secret {masterSecret}')
                    LOGGER.info(f'master secret encrepted {encreptedMastersSecret}')

                    self.client.send(encreptedMastersSecret)
                    key = scrypt(masterSecret, nonce, 32, N=2 ** 14, r=8, p=1,num_keys=2)
                    LOGGER.info(f'key on sender side {key}')
                    self.Key.set_var(Key=key[0], hash_key=key[1], iv=bytes(masterSecret[:16],'utf-8'), nonce=nonce[:16], master_secret=masterSecret)
                    self.chatS(name1,name2)
                else :
                    pass
                break

            else:
                LOGGER.info('somthing wrong with the reciver certificate')
                self.client.send('wrong certificate')


    def handShakingClient(self, name1, name2):
        # hello message
        m = self.reciverTCP.recv(self.bufferSize)
        LOGGER.info(f'hello message is here : {m}')
        recv = self.reciverTCP.recv(self.bufferSize)
        LOGGER.info(f'receiver got the first user certificate: {recv}')
        while True:
            self.serverTCP.send(bytes('Certificate', 'utf-8'))
            self.serverTCP.send(recv)
            LOGGER.info('Waiting for server to send certificate check')
            check = self.serverTCP.recv(self.bufferSize)
            LOGGER.info(f' {name2} received {check}')
            if check.decode() == 'pass':
                userCertificate = x509.load_pem_x509_certificate(recv)
                LOGGER.info(f'{name2} - certificate check done')
                nonce= uuid.uuid4().hex
                self.reciverTCP.send(bytes(nonce, 'utf-8'))
                self.reciverTCP.send(self.certificate.public_bytes(serialization.Encoding.PEM))
                LOGGER.info(f'{name1} sent his certificate')
                encoded_key = open(f"K{name2}-.pem", "rb").read()
                pass_phrase = self.pass_phrase.encode()
                myKey = load_pem_private_key(encoded_key, password = pass_phrase)
                encreptedNonce = self.reciverTCP.recv(self.bufferSize)
                LOGGER.info(f'recived nonce is {encreptedNonce} {type(encreptedNonce)}')
                decreptedNonce = myKey.decrypt(
                                    encreptedNonce,
                                    padding.OAEP(
                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None))
                LOGGER.info(f'recived nonce is {decreptedNonce} {type(decreptedNonce)}')
                LOGGER.info(f'our nonce is {nonce} {type(nonce)} ')
                if decreptedNonce == bytes(nonce,'utf-8'):
                    self.reciverTCP.send(bytes('true', 'utf-8'))
                    encreptedMasterSecret = self.reciverTCP.recv(self.bufferSize)
                    LOGGER.info(f'recived nonce is {encreptedMasterSecret} {type(encreptedMasterSecret)}')
                    decreptedMasterSecret = myKey.decrypt(
                        encreptedMasterSecret,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None))
                    LOGGER.info(f'received nonce is {decreptedMasterSecret} {type(decreptedMasterSecret)}')
                    key = scrypt(decreptedMasterSecret, nonce, 32, N=2 ** 14, r=8, p=1,num_keys=2)
                    LOGGER.info(f'key on receiver side {key}')
                    self.Key.set_var(Key=key[0], hash_key=key[1], iv=decreptedMasterSecret[:16], nonce=nonce[:16],
                            master_secret=str(decreptedMasterSecret))

                    self.chatR(name1,name2)
                else:
                    self.reciverTCP.send(bytes('false', 'utf-8'))

                break

            else:
                LOGGER.info('Something wrong')
                self.reciverTCP.send('wrong certificate')
                # nonce = self.client.recv(self.bufferSize)
                # userCertificate = x509.load_pem_x509_certificate(self.client.recv(self.bufferSize))


class GUI(Frame):
    def __init__(self, parent):
        Frame.__init__(self, parent)
        self.parent = parent
        self.client = Client()
        self.options()

    def options(self):
        self.client.TCPConnection()
        Label(text="Choose Login Or Register", bg='#856ff8', width="300", height="2", font=("Calibri", 13)).pack()
        Label(text="").pack()
        # create Login Button
        Button(text="Login", height="2", width="30", command=self.login).pack()
        Label(text="").pack()
        # create a register button
        Button(text="Register", height="2", width="30", command=self.register).pack()

    def register(self):
        self.client.getType('NEW')
        self.register_screen = Toplevel(self.parent)
        self.register_screen.title("Register")
        self.register_screen.geometry("300x250")
        self.username = StringVar()
        self.password = StringVar()
        Label(self.register_screen, text="Please enter details below", bg='#856ff8').pack()
        Label(self.register_screen, text="").pack()
        username_lable = Label(self.register_screen, text="Username * ")
        username_lable.pack()
        self.username_entry = Entry(self.register_screen, textvariable=self.username)
        self.username_entry.pack()
        password_lable = Label(self.register_screen, text="Password * ")
        password_lable.pack()
        self.password_entry = Entry(self.register_screen, textvariable=self.password, show='*')
        self.password_entry.pack()
        Label(self.register_screen, text="").pack()
        Button(self.register_screen, text="Register", width=10, height=1, bg='#856ff8',
               command=lambda: self.sendLogInData(0)).pack()

    def login(self):
        self.client.getType('OLD')
        self.login_screen = Toplevel(self.parent)
        self.login_screen.title("Login")
        self.login_screen.geometry("300x250")
        Label(self.login_screen, text="Please enter details below to login").pack()
        Label(self.login_screen, text="").pack()
        self.username = StringVar()
        self.password = StringVar()
        Label(self.login_screen, text="Username * ").pack()
        self.username_login_entry = Entry(self.login_screen, textvariable=self.username)
        self.username_login_entry.pack()
        Label(self.login_screen, text="").pack()
        Label(self.login_screen, text="Password * ").pack()
        self.password__login_entry = Entry(self.login_screen, textvariable=self.password, show='*')
        self.password__login_entry.pack()
        Label(self.login_screen, text="").pack()
        Button(self.login_screen, text="Login", width=10, height=1, command=lambda: self.sendLogInData(1)).pack()

    def waitOrSearch(self):
        waitOrSearch_screen = Toplevel(self.parent)
        waitOrSearch_screen.title(f"search {self.username.get()}")
        waitOrSearch_screen.geometry("300x250")
        Label(waitOrSearch_screen, text="search or wait", bg='#856ff8', width="300", height="2",
              font=("Calibri", 13)).pack()
        Label(waitOrSearch_screen, text="").pack()
        # create Login Button
        Button(waitOrSearch_screen, text="search", height="2", width="30",
               command=lambda: [self.search(), waitOrSearch_screen.destroy()]).pack()
        Label(waitOrSearch_screen, text="").pack()
        # create a register button
        Button(waitOrSearch_screen, text="waite", height="2", width="30",
               command=lambda: [self.wait(), waitOrSearch_screen.destroy()]).pack()

    def waiting(self):
        self.waiting_screen = Toplevel(self.parent)
        self.waiting_screen.title(f"wait {self.username.get()}")
        self.waiting_screen.geometry("300x250")
        Label(self.waiting_screen, text="waiting for other users to join the app").pack()
        Button(self.waiting_screen, text="check", height="2", width="30",
               command=self.waitForUsers).pack()

    def wait(self):
        self.client.searchOrWait('NO')
        rcv = threading.Thread(target=self.acceptRequist)
        rcv.start()

        self.wait_screen = Toplevel(self.parent)
        self.wait_screen.title(f"wait {self.username.get()}")
        self.wait_screen.geometry("300x250")
        Label(self.wait_screen, text="waiting for other user to contact you").pack()
        Label(self.wait_screen, text="").pack()
        Label(self.wait_screen, text="or you can go and search").pack()
        Button(self.wait_screen, text="search", width=10, height=1,
               command=lambda: [self.waitOrSearch(), self.wait_screen.destroy()]).pack()

    def search(self):
        self.client.searchOrWait('OK')
        self.search_screen = Toplevel(self.parent)
        self.search_screen.title(f"search {self.username.get()}")
        self.search_screen.geometry("300x250")
        Label(self.search_screen, text="Please enter details below to find user").pack()
        Label(self.search_screen, text="").pack()
        name = StringVar()
        Label(self.search_screen, text="Username * ").pack()
        username_login_entry = Entry(self.search_screen, textvariable=name)
        username_login_entry.pack()
        Label(self.search_screen, text="").pack()
        Button(self.search_screen, text="search", width=10, height=1,
               command=lambda: [self.searchRequist(name.get())]).pack()

    def sendLogInData(self, t):
        r = self.client.sendLogInData(self.username.get(), self.password.get())
        if r == 'pass':
            self.client.gettingRSAKeys(self.username.get())
            self.waiting()
            if (t == 1):
                self.login_screen.destroy()
            else:
                self.register_screen.destroy()
        else:
            if (t == 1):
                self.username_login_entry.delete(0, END)
                self.password__login_entry.delete(0, END)
                Label(self.login_screen, text=r).pack()
            else:
                self.password_entry.delete(0, END)
                self.username_entry.delete(0, END)
                Label(self.register_screen, text=r).pack()

    def waitForUsers(self):
        r = self.client.waitForUsers()
        print(r)
        if r == 'ENTER':
            LOGGER.info('another user here')
            self.waiting_screen.destroy()
            self.waitOrSearch()

    def searchRequist(self, name):
        print(name)
        rcv = threading.Thread(target=self.getSearchResult, args=(name,))
        rcv.start()

    def getSearchResult(self, name):
        msgFromServer = self.client.search(name)
        if msgFromServer['address'] == 'BUSY':
            Label(self.search_screen, text=msgFromServer).pack()
        else:
            self.client.createChatConnection(msgFromServer['address'])
            self.search_screen.destroy()
            LOGGER.info(f'{self.username} - i am entering the handshaking')
            state = self.client.handShakingServer(self.username.get(), msgFromServer['name'])
            # state = self.client.chatS(self.username.get(), msgFromServer['name'])
            if state == 'LOGOUT':
                self.waiting()

    def acceptRequist(self):
        msgFromServer = self.client.wait()
        if len(msgFromServer) != 0:
            self.client.connectToChat(msgFromServer['address'])
            self.wait_screen.destroy()
            LOGGER.info('receiver entered the handshaking')
            state = self.client.handShakingClient(msgFromServer['name'], self.username.get())
            # state=self.client.chatR(msgFromServer['name'], self.username.get())
            if state == 'LOGOUT':
                self.waiting()


def main():
    root = Tk()
    root.geometry("300x250")
    root.title("Account Login")
    app = GUI(root)
    root.mainloop()


main()
