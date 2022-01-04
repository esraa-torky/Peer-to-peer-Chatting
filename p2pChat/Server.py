import socket
import threading

class Server:
    def __init__(self):
        self.ip = '127.0.0.1'
        self.port = 1234
        # creating the TCP socket
        self.serverTCP = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverTCP.bind((self.ip, self.port))
        self.ThreadCount =0
        self.clients = []

    def threaded_client(self,connection,address):
        #connection.send(str.encode('Welcome to the Servern'))
        name = connection.recv(1024).decode('utf-8')
        password = connection.recv(1024).decode('utf-8')
        self.clients.append({'name': name, 'password': password, 'address': address})
        while True:
            data = connection.recv(2048).decode('utf-8')
            print(data)
            #reply = 'Server Says: ' + data.decode('utf-8')
            if not data:
                break
            #connection.sendall(str.encode(reply))
        connection.close()
    def newClinet(self):
        self.serverTCP.listen(5)
        while True:
            client, address = self.serverTCP.accept()
            print('new client', str(address[0]), ':', str(address[1]))
            self.threaded_client(client, address)
            self.ThreadCount += 1
            print(self.clients)
            print(self.ThreadCount)
            # while True:
            #     messg=client.recv(1024).decode('utf-8')
            #     if (messg=='LOG OUT'):
            #         client.close()
            #         break
            #         print('discontcted')
            #     else:
            #         print(messg)
def main():
    server = Server()
    server.newClinet()


main()
