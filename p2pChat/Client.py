import threading
from threading import Thread
from tkinter import *
import socket
import json
import time


class Client(Thread):
    def __init__(self):
        super().__init__()
        self.ip = "127.0.0.1"
        self.port = 20001
        self.bufferSize = 1024

    def TCPConnection(self):
        # creating the TCP socket
        self.serverTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverTCP.connect((self.ip, 1234))
        print(self.serverTCP.recv(self.bufferSize).decode('utf-8'))

    def getType(self,type):
        self.serverTCP.send(bytes(type, 'utf-8'))

    def sendLogInData(self,username,password):
        print('here')
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
        print('waiting')
    def getSearchResult(self):
        msgFromServer = self.serverTCP.recv(self.bufferSize).decode('utf-8')
        print(msgFromServer)
        return msgFromServer
    def wait(self):
        msgFromServer = self.serverTCP.recv(self.bufferSize).decode('utf-8')
        print(msgFromServer)
        return msgFromServer
    def answerRequist(self):
        self.serverTCP.send(bytes('OK', 'utf-8'))
        # return 'OK'

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
        search_screen = Toplevel(self.parent)
        search_screen.title("search")
        search_screen.geometry("300x250")
        Label(search_screen, text="Please enter details below to find user").pack()
        Label(search_screen, text="").pack()
        name = StringVar()
        Label(search_screen, text="Username * ").pack()
        username_login_entry = Entry(search_screen, textvariable=name)
        username_login_entry.pack()
        Label(search_screen, text="").pack()
        Button(search_screen, text="search", width=10, height=1, command=lambda: [self.searchRequist(name.get())]).pack()

    def chat(self):
        #self.name = name
        # to show chat window
        self.Window =Toplevel(self.parent)
        self.Window.title("CHATROOM")
        self.Window.resizable(width=False,
                              height=False)
        self.Window.configure(width=470,
                              height=550,
                              bg="#17202A")
        self.labelHead = Label(self.Window,
                               bg="#17202A",
                               fg="#EAECEE",
                               text='name',
                               font="Helvetica 13 bold",
                               pady=5)

        self.labelHead.place(relwidth=1)
        self.line = Label(self.Window,
                          width=450,
                          bg="#ABB2B9")

        self.line.place(relwidth=1,
                        rely=0.07,
                        relheight=0.012)

        self.textCons = Text(self.Window,
                             width=20,
                             height=2,
                             bg="#17202A",
                             fg="#EAECEE",
                             font="Helvetica 14",
                             padx=5,
                             pady=5)

        self.textCons.place(relheight=0.745,
                            relwidth=1,
                            rely=0.08)

        self.labelBottom = Label(self.Window,
                                 bg="#ABB2B9",
                                 height=80)

        self.labelBottom.place(relwidth=1,
                               rely=0.825)

        self.entryMsg = Entry(self.labelBottom,
                              bg="#2C3E50",
                              fg="#EAECEE",
                              font="Helvetica 13")

        # place the given widget
        # into the gui window
        self.entryMsg.place(relwidth=0.74,
                            relheight=0.06,
                            rely=0.008,
                            relx=0.011)

        self.entryMsg.focus()

        # create a Send Button
        self.buttonMsg = Button(self.labelBottom,
                                text="Send",
                                font="Helvetica 10 bold",
                                width=20,
                                bg="#ABB2B9",
                                command=lambda: self.sendButton(self.entryMsg.get()))

        self.buttonMsg.place(relx=0.77,
                             rely=0.008,
                             relheight=0.06,
                             relwidth=0.22)

        self.textCons.config(cursor="arrow")

        # create a scroll bar
        scrollbar = Scrollbar(self.textCons)

        # place the scroll bar
        # into the gui window
        scrollbar.place(relheight=1,
                        relx=0.974)

        scrollbar.config(command=self.textCons.yview)

        self.textCons.config(state=DISABLED)

        # function to basically start the thread for sending messages

    # def sendButton(self, msg):
    #     self.textCons.config(state=DISABLED)
    #     self.msg = msg
    #     self.entryMsg.delete(0, END)
    #     snd = threading.Thread(target=self.sendMessage)
    #     snd.start()

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
        self.client.search(name)
        rcv = threading.Thread(target=self.client.getSearchResult)
        rcv.start()
        if rcv =='OK':
            self.chat()
    def acceptRequist(self):
        m=self.client.wait()
        if m=='REQUEST':
            Button(self.wait_screen, text="accept", width=10, height=1,
                   command=lambda: [self.sendAnswer()]).pack()
            #self.chat()
    def sendAnswer(self):
        self.client.answerRequist()
        self.chat()
        self.wait_screen.destroy()
def main():
    root = Tk()
    root.geometry("300x250")
    root.title("Account Login")
    app = GUI(root)
    root.mainloop()


main()
