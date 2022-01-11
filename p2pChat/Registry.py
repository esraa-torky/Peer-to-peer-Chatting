import socket
import _thread
import json



class Server:
    def __init__(self):
        self.ipUDP = "127.0.0.1"
        self.portUDP = 20001
        self.bufferSize = 1024
        self.clients = []
        self.onlineClients = []
        self.serverUDP = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.serverUDP.bind((self.ipUDP, self.portUDP))
        # creating the TCP socket
        self.serverTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverTCP.bind((self.ipUDP, 1234))


    def readUsers(self):
        file = open('users.txt', 'r')
        for i in file.readlines():
            self.clients.append({'name': i.split(' ')[0], 'password': i.split()[1]})
        file.close()

    def addUserToFile(self, name, password):
        file = open('users.txt', 'a')
        file.write('\n')
        file.write(name + ' ')
        file.write(password)
        file.close()

    def login_threaded(self, connection, address):
        self.readUsers()
        connection.send(bytes('Welcome to the Server write NEW for new account or OLD if you have an account', 'utf-8'))
        userType = connection.recv(1024).decode('utf-8')
        found = False
        print(userType)
        if userType == 'NEW':
            while True:
                name = connection.recv(1024).decode('utf-8')
                password = connection.recv(1024).decode('utf-8')
                for i in self.clients:
                    if i['name'] == name:
                        found = True
                        break
                if found:
                    connection.send(bytes('try new username', 'utf-8'))
                    found = False
                else:
                    client = {'name': name, 'password': password, 'address': address,
                              'client': connection, 'state': 'HERE'}
                    self.onlineClients.append(client)
                    self.addUserToFile(name, password)
                    connection.send(bytes('pass', 'utf-8'))
                    break
        elif userType == 'OLD':
            while True:
                name = connection.recv(1024).decode('utf-8')
                password = connection.recv(1024).decode('utf-8')
                for i in self.clients:
                    if i['name'] == name and i['password'] == password:
                        found = True
                        break
                if found:
                    here=False
                    for i in self.onlineClients:
                        if i['name'] == name:
                            connection.send(bytes('already online on another machine', 'utf-8'))
                            here =True
                            break
                    if not here:
                        client={'name': name, 'password': password, 'address': address,
                                                   'client': connection, 'state': 'HERE','UDPaddress':''}
                        self.onlineClients.append(client)
                        connection.send(bytes('pass', 'utf-8'))
                        print('DONE')
                        break
                else:
                    connection.send(bytes('user name or password is wrong !!', 'utf-8'))
        self.checkConnection(client)


    def UDPConnection(self,client):
        bytesAddressPair = self.serverUDP.recvfrom(self.bufferSize)
        message = bytesAddressPair[0]
        address = bytesAddressPair[1]
        clientMsg = "Message from Client:{}".format(message)
        clientIP = "Client IP Address:{}".format(address)
        self.onlineClients[self.onlineClients.index(client)]['UDPaddress'] = address
        print(clientMsg)
        print(clientIP)
        print('first')
        while True:
            bytesAddressPair = self.serverUDP.recvfrom(self.bufferSize)
            message = bytesAddressPair[0]
            address = bytesAddressPair[1]
            clientMsg = "Message from Client:{}".format(message)
            clientIP = "Client IP Address:{}".format(address)
            self.onlineClients[self.onlineClients.index(client)]['UDPaddress'] = address
            print(clientMsg)
            print(clientIP)


    def checkConnection(self, client):
        while True:
            print(client['client'].recv(1024).decode('utf-8'))
            if len(self.onlineClients) > 1:
                client['client'].send(b'ENTER')
                r=client['client'].recv(1024).decode('utf-8')
                print(r)
                if r != 'NO':
                    self.onlineClients[self.onlineClients.index(client)]['state'] = 'searching'
                    self.search(client)
                    break
                else:
                    self.onlineClients [self.onlineClients.index(client)]['state'] = 'waiting'
                    client['state'] = 'waiting'
            else:
                client['client'].send(b'nothing')

    def search(self,client):
        while True:
            name=client['client'].recv(1024).decode('utf-8')
            print(name)
            found=False
            for i in self.onlineClients:
                if name == i['name']:
                    found=True
                    reciver=i
            if found and reciver['state'] == 'waiting':
                data1 = json.dumps({"address":client['address'] , "name": reciver['name']})
                client['client'].send(data1.encode())
                self.onlineClients[self.onlineClients.index(client)]['state'] = 'chatting'
                data2 = json.dumps({"address": client['address'], "name": client['name']})
                reciver['client'].send(data2.encode())
                self.onlineClients[self.onlineClients.index(reciver)]['state'] = 'chatting'

            else:
                data2 = json.dumps({"address":'BUSY'})
                client['client'].send(data2.encode())

    def chat(self,client1,client2):
        while True:
            msg1=client1.recv(self.bufferSize)
            client2.send(msg1)
            msg2 = client2.recv(self.bufferSize)
            client1.send(msg2)
            if msg2 == 'LOG OUT' or msg1 == 'LOG OUT':
                break

    def TCPConnection(self):
        self.serverTCP.listen(5)
        client, address = self.serverTCP.accept()
        print('accepted')
        _thread.start_new_thread(self.login_threaded, (client,address))
        print(self.onlineClients)


def main():
    server = Server()
    while True:
        server.TCPConnection()





main()
