import socket


class Clinet:
    def __init__(self):
        self.ip = '127.0.0.1'
        self.port = 1234
        # creating the TCP socket
        self.serverTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverTCP.connect((self.ip, self.port))

    def getinfo(self):
        print(self.serverTCP.recv(1024).decode('utf-8'))
        self.serverTCP.send(bytes(input(), 'utf-8'))
        while True:
            name = input('user name :')
            password = input('password :')
            self.serverTCP.send(bytes(name, 'utf-8'))
            self.serverTCP.send(bytes(password, 'utf-8'))
            respond = self.serverTCP.recv(1024).decode('utf-8')
            if respond == 'pass':
                print(respond)
                break
            else:
                print(respond)

def main():
    clinet = Clinet()
    clinet.getinfo()


main()
