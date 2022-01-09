import socket


class Client:
    def __init__(self):
        self.ip = "127.0.0.1"
        self.port = 20001
        self.bufferSize = 1024
        self.TCPConnection()

    def getinfo(self):
        print(self.serverTCP.recv(self.bufferSize).decode('utf-8'))
        self.serverTCP.send(bytes(input(), 'utf-8'))
        while True:
            name = input('user name :')
            password = input('password :')
            self.serverTCP.send(bytes(name, 'utf-8'))
            self.serverTCP.send(bytes(password, 'utf-8'))
            respond = self.serverTCP.recv(self.bufferSize).decode('utf-8')
            if respond == 'pass':
                print(respond)
                break
            else:
                print(respond)
    def TCPConnection(self):
        # creating the TCP socket
        self.serverTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverTCP.connect((self.ip, 1234))
        self.getinfo()
    def UDPConnection(self):
        self.serverUDP = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        msgFromClient = "Hello UDP Server"
        bytesToSend = str.encode(msgFromClient)
        self.serverUDP.sendto(bytesToSend, (self.ip, self.port))
        msgFromServer = self.serverUDP.recvfrom(self.bufferSize)
        msg = "Message from Server {}".format(msgFromServer[0])
        print(msg)
        self.connectToPeer()

    def connectToPeer (self):
        # while True:
            print('waiting for other Users..')
            msgFromServer = self.serverUDP.recvfrom(self.bufferSize)
            print(msgFromServer)
            name=input('search >>')
            self.serverUDP.sendto(bytes(name, 'utf-8'), (self.ip, self.port))
            msgFromServer = self.serverUDP.recvfrom(self.bufferSize)
            print(msgFromServer)


def main():
    client = Client()
    client.UDPConnection()


main()
