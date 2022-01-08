import socket


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
        self.TCPConnection()

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
                    self.onlineClients.append({'name': name, 'password': password, 'address': address})
                    self.addUserToFile(name, password)
                    connection.send(bytes('pass', 'utf-8'))
                    break
        elif userType == 'OLD':
            while True:
                name = connection.recv(1024).decode('utf-8')
                password = connection.recv(1024).decode('utf-8')
                for i in self.clients:
                    if i['name'] == name and i['password'] == password:
                        self.onlineClients.append({'name': name, 'password': password, 'address': address})
                        found = True
                        break
                if found:
                    connection.send(bytes('pass', 'utf-8'))
                    print('DONE')
                    break
                else:
                    connection.send(bytes('user name or password is wrong !!', 'utf-8'))
        connection.close()
        self.UDPConnection()

    def UDPConnection(self):
        msgFromServer = "Hello UDP Client"
        bytesToSend = str.encode(msgFromServer)
        bytesAddressPair = self.serverUDP.recvfrom(self.bufferSize)
        message = bytesAddressPair[0]
        address = bytesAddressPair[1]
        clientMsg = "Message from Client:{}".format(message)
        clientIP = "Client IP Address:{}".format(address)
        print(clientMsg)
        print(clientIP)
        self.serverUDP.sendto(bytesToSend, address)

    def TCPConnection(self):
        self.serverTCP.listen(5)
        while True:
            client, address = self.serverTCP.accept()
            print('accepted')
            self.login_threaded(client, address)


def main():
    server = Server()


main()
