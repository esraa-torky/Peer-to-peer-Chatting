import socket


class Clinet:
    def __init__(self):
        self.ip = '127.0.0.1'
        self.port = 1234
        # creating the TCP socket
        self.serverTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverTCP.connect((self.ip, self.port))

    def getinfo(self):
        name = input('user name :')
        password = input('password')
        self.serverTCP.send(bytes(name, 'utf-8'))
        self.serverTCP.send(bytes(password, 'utf-8'))
        while True:
            m = input('write your message')
            message = self.serverTCP.send(bytes(m, 'utf-8'))
            if m == 'LOG OUT':
                break

def main():
    clinet = Clinet()
    clinet.getinfo()


main()
