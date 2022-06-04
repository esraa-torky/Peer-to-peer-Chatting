import threading
from threading import Thread
from tkinter import *
import socket
import json
import logging
import colorama

from p2pChat.CustomFormatter import CustomFormatter
from p2pChat.security import decrypt_msg, encrypt_msg

colorama.init()
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import Poly1305
from Crypto.Protocol.KDF import scrypt

import time

LOG_PATH = 'p2pChat/logs'
LOG_FILE_NAME = 'client'
logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
rootLogger = logging.getLogger("CLIENT")

fileHandler = logging.FileHandler("{0}/{1}.log".format(LOG_PATH, LOG_FILE_NAME))
fileHandler.setFormatter(logFormatter)
rootLogger.addHandler(fileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
rootLogger.addHandler(consoleHandler)
rootLogger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)

ch.setFormatter(CustomFormatter())
rootLogger.addHandler(ch)



class Client(Thread):
    def __init__(self):
        super().__init__()
        self.ip = "127.0.0.1"
        self.port = 20001
        self.bufferSize = 1024
        self.serverUDP = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    def createMessagesfile(self,name):
        file = open(name+'.txt', 'a')
        return file

    def saveMessages(self,name,message):
        file=open(name + '.txt', 'a')
        file.write(message +'\n')
        file.close()

    def TCPConnection(self):
        # creating the TCP socket
        self.serverTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverTCP.connect((self.ip, 1234))
        print(self.serverTCP.recv(self.bufferSize).decode('utf-8'))

    def getType(self,type):
        self.serverTCP.send(bytes(type, 'utf-8'))

    def sendLogInData(self,username,password):
        self.serverTCP.send(bytes(username, 'utf-8'))
        self.serverTCP.send(bytes(password, 'utf-8'))
        respond = self.serverTCP.recv(self.bufferSize).decode('utf-8')
        return respond

    def waitForUsers(self):
        self.serverTCP.send(bytes('check', 'utf-8'))
        msgFromServer = self.serverTCP.recv(self.bufferSize).decode('utf-8')
        return msgFromServer

    def searchOrWait(self,check):
        self.serverTCP.send(bytes(check, 'utf-8'))

    def search(self,name):
        self.serverTCP.send(bytes(name, 'utf-8'))
        msgFromServer = self.serverTCP.recv(self.bufferSize)
        msgFromServer=json.loads(msgFromServer.decode())
        return msgFromServer

    def wait(self):
        msgFromServer = self.serverTCP.recv(self.bufferSize)
        msgFromServer = json.loads(msgFromServer.decode())
        return msgFromServer

    # def sendHalloToUDP(self):
    #     msgFromClient = "Hello UDP Server"
    #     bytesToSend = str.encode(msgFromClient)
    #     self.serverUDP.sendto(bytesToSend, (self.ip, self.port))

    def createChatConnection(self,address):
        clientTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientTCP.bind((address[0], address[1]))
        clientTCP.listen(1)
        self.client, address = clientTCP.accept()
        # client.send(bytes('welcome', 'utf-8'))

    def connectToChat(self,address):
        self.reciverTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.reciverTCP.connect((address[0], address[1]))

    def chatR(self,name1,name2):
        while True:
            received_msg = self.reciverTCP.recv(self.bufferSize)
            digest = self.reciverTCP.recv(self.bufferSize)
            msg = decrypt_msg(digest=digest, encrypted_data=received_msg)
            m=name1+': '+msg.decode()
            if m== 'LOGOUT':
                print(m)
                return'LOGOUT'
            else:
                print(m)
            mesge=input(name2+': ')
            if mesge == 'LOGOUT':
                self.reciverTCP.send(bytes(mesge,'utf-8'))
                self.reciverTCP.close()
                self.serverTCP.send(bytes('LOGOUT','utf-8'))
                self.serverTCP.recv(self.bufferSize)
                break
            else:
                self.reciverTCP.send(bytes(mesge, 'utf-8'))

    def chatS(self,name1,name2):
        while True:
            mesge = input(name1 + ': ')
            self.saveMessages(name1+'_'+name2, name1+': '+mesge)
            if mesge == 'LOGOUT':
                self.client.send(bytes(mesge, 'utf-8'))
                self.client.close()
                self.serverTCP.send(bytes('LOGOUT','utf-8'))
                self.serverTCP.recv(self.bufferSize)
                break
            else:
                data, digest = encrypt_msg(mesge)
                self.client.send(bytes(data))
                self.client.send(bytes(digest))
            m = name2+': '+self.client.recv(self.bufferSize).decode()
            self.saveMessages(name1+'_'+name2, m)
            if m=='LOGOUT':
                print(m)
                return 'LOGOUT'
            else:
                print(m)


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
        Button(text="Login", height="2", width="30",command=self.login).pack()
        Label(text="").pack()
        # create a register button
        Button(text="Register", height="2", width="30",command=self.register).pack()

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
        Button(self.register_screen, text="Register", width=10, height=1, bg='#856ff8',command=lambda:self.sendLogInData(0)).pack()

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
        Button(self.login_screen, text="Login", width=10, height=1, command=lambda:self.sendLogInData(1)).pack()

    def waitOrSearch(self):
        waitOrSearch_screen = Toplevel(self.parent)
        waitOrSearch_screen.title("search")
        waitOrSearch_screen.geometry("300x250")
        Label(waitOrSearch_screen,text="search or wait", bg='#856ff8', width="300", height="2", font=("Calibri", 13)).pack()
        Label(waitOrSearch_screen,text="").pack()
        # create Login Button
        Button(waitOrSearch_screen,text="search", height="2", width="30", command=lambda:[self.search(),waitOrSearch_screen.destroy()]).pack()
        Label(waitOrSearch_screen,text="").pack()
        # create a register button
        Button(waitOrSearch_screen,text="waite", height="2", width="30",command=lambda:[self.wait(),waitOrSearch_screen.destroy()]).pack()

    def waiting(self):
        self.waiting_screen = Toplevel(self.parent)
        self.waiting_screen.title("wait")
        self.waiting_screen.geometry("300x250")
        Label(self.waiting_screen, text="waiting for other users to join the app").pack()
        Button(self.waiting_screen, text="check", height="2", width="30",
               command=self.waitForUsers).pack()

    def wait(self):
        rcv = threading.Thread(target=self.acceptRequist)
        rcv.start()
        self.client.searchOrWait('NO')
        self.wait_screen = Toplevel(self.parent)
        self.wait_screen.title("wait")
        self.wait_screen.geometry("300x250")
        Label(self.wait_screen, text="waiting for other user to contact you").pack()
        Label(self.wait_screen, text="").pack()
        Label(self.wait_screen, text="or you can go and search").pack()
        Button(self.wait_screen, text="search", width=10, height=1,command=lambda: [self.waitOrSearch(), self.wait_screen.destroy()]).pack()

    def search(self):
        self.client.searchOrWait('OK')
        self.search_screen = Toplevel(self.parent)
        self.search_screen.title("search")
        self.search_screen.geometry("300x250")
        Label(self.search_screen, text="Please enter details below to find user").pack()
        Label(self.search_screen, text="").pack()
        name = StringVar()
        Label(self.search_screen, text="Username * ").pack()
        username_login_entry = Entry(self.search_screen, textvariable=name)
        username_login_entry.pack()
        Label(self.search_screen, text="").pack()
        Button(self.search_screen, text="search", width=10, height=1, command=lambda: [self.searchRequist(name.get())]).pack()

    def sendLogInData(self,t):
        r=self.client.sendLogInData(self.username.get(),self.password.get())
        if r=='pass':
            self.waiting()
            if(t==1):
                self.login_screen.destroy()
            else:
                self.register_screen.destroy()
        else:
            if(t==1):
                self.username_login_entry.delete(0, END)
                self.password__login_entry.delete(0, END)
                Label(self.login_screen, text=r).pack()
            else:
                self.password_entry.delete(0,END)
                self.username_entry.delete(0,END)
                Label(self.register_screen, text=r).pack()

    def waitForUsers(self):
        r = self.client.waitForUsers()
        print(r)
        if r == 'ENTER':
            self.waiting_screen.destroy()
            self.waitOrSearch()

    def searchRequist(self,name):
        print(name)
        rcv = threading.Thread(target=self.getSearchResult, args=(name,))
        rcv.start()

    def getSearchResult(self,name):
        msgFromServer = self.client.search(name)
        if msgFromServer['address'] == 'BUSY':
            Label(self.search_screen, text=msgFromServer).pack()
        else:
            self.client.createChatConnection(msgFromServer['address'])
            self.search_screen.destroy()
            state=self.client.chatS(self.username.get(),msgFromServer['name'])
            if state == 'LOGOUT':
                self.waiting()

    def acceptRequist(self):
        msgFromServer=self.client.wait()
        if len(msgFromServer)!=0:
            self.client.connectToChat(msgFromServer['address'])
            self.wait_screen.destroy()
            state=self.client.chatR(msgFromServer['name'], self.username.get())
            if state == 'LOGOUT':
                self.waiting()



def main():
    root = Tk()
    root.geometry("300x250")
    root.title("Account Login")
    app = GUI(root)
    root.mainloop()


main()
