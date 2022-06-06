import datetime
import _thread
import socket
import json
import logging
import colorama
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat._oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography import x509
from cryptography.x509 import Certificate

from CustomFormatter import CustomFormatter
from security import generateRSAKeys

LOG_PATH = 'p2pChat/logs'
LOG_FILE_NAME = 'client'
logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
LOGGER = logging.getLogger("SERVER")

fileHandler = logging.FileHandler("logs/server.log")
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

colorama.init()


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
        generateRSAKeys('server')

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
        userType = connection.recv(4096).decode('utf-8')
        found = False
        if userType == 'NEW':
            while True:
                name = connection.recv(4096).decode('utf-8')
                password = connection.recv(4096).decode('utf-8')
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
                    # get public key
                    userKey = connection.recv(1024)
                    # create certificate and send it to client
                    connection.send(self.createCertificate(userKey, name))
                    # check if the client get his certificate correctly
                    while True:
                        check = connection.recv(1024).decode('utf-8')
                        if check == 'pass':
                            print('all is good certificate')
                            break
                        else:
                            print('bad')
                            # get public key
                            userKey = connection.recv(1024)
                            # create certificate and send it to client
                            connection.send(self.createCertificate(userKey, name))
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
                    here = False
                    for i in self.onlineClients:
                        if i['name'] == name:
                            connection.send(bytes('already online on another machine', 'utf-8'))
                            here = True
                            break
                    if not here:
                        client = {'name': name, 'password': password, 'address': address,
                                  'client': connection, 'state': 'HERE', 'UDPaddress': ''}
                        self.onlineClients.append(client)
                        connection.send(bytes('pass', 'utf-8'))
                        # get public key
                        userKey = connection.recv(1024)
                        print('key is here')
                        # create certificate and send it to client
                        connection.send(self.createCertificate(userKey, name))
                        # check if the client get his certificate correctly
                        while True:
                            check = connection.recv(1024).decode('utf-8')
                            if check == 'pass':
                                break
                            else:
                                # get public key again
                                userKey = connection.recv(1024)
                                # create certificate and send it to client again
                                connection.send(self.createCertificate(userKey, name))
                        break
                else:
                    connection.send(bytes('user name or password is wrong !!', 'utf-8'))
            self.checkConnection(client)

    def checkConnection(self, client):
        while True:
            check = client['client'].recv(1024).decode('utf-8')
            LOGGER.info(check)
            if len(self.onlineClients) > 1:
                client['client'].send(b'ENTER')
                r = client['client'].recv(1024).decode('utf-8')
                print(r)
                if r != 'NO':
                    self.onlineClients[self.onlineClients.index(client)]['state'] = 'searching'
                    self.search(client)
                    break
                else:
                    self.onlineClients[self.onlineClients.index(client)]['state'] = 'waiting'
                    client['state'] = 'waiting'
                    self.serverWait(client)
                    break
            else:
                client['client'].send(b'nothing')
        LOGGER.info('loop is done')

    def serverWait(self,client):

        while True:
            check = client['client'].recv(1024)
            LOGGER.info(f'recived {check} from the user ')
            # check = b'Certificate'
            if check == b'Certificate':
                name = client['name']
                LOGGER.info(f'got certificate from client {name}')
                self.checkCertificate(client)
            else:
                pass


    def search(self, client):
        while True:
            name = client['client'].recv(1024).decode('utf-8')
            print(name)
            found = False
            for i in self.onlineClients:
                if name == i['name']:
                    found = True
                    reciver = i
            if found and reciver['state'] == 'waiting':
                data1 = json.dumps({"address": client['address'], "name": reciver['name']})
                client['client'].send(data1.encode())
                self.onlineClients[self.onlineClients.index(client)]['state'] = 'chatting'
                data2 = json.dumps({"address": client['address'], "name": client['name']})
                reciver['client'].send(data2.encode())
                self.onlineClients[self.onlineClients.index(reciver)]['state'] = 'chatting'
                # check the sender certificate
                self.serverWait(client)
                # if client['client'].recv(self.bufferSize).decode('utf-8') == 'LOGOUT':
                #     reciver['client'].send(bytes('BACK', 'utf-8'))
                #     client['client'].close()
                #     self.onlineClients.pop(self.onlineClients.index(client))
                #     self.onlineClients[self.onlineClients.index(reciver)]['state'] = 'HERE'
            else:
                data2 = json.dumps({"address": 'BUSY'})
                client['client'].send(data2.encode())

    def TCPConnection(self):
        self.serverTCP.listen(10)
        client, address = self.serverTCP.accept()
        print('accepted')
        _thread.start_new_thread(self.login_threaded, (client, address))

    def createCertificate(self, userKey, username):
        pass_phrase = "SECURITY_HW_1".encode()
        userKey = load_pem_public_key(userKey)
        subject = x509.Name([
            x509.NameAttribute(NameOID.GIVEN_NAME, username), ])
        # get server keys
        # encoded_key = open("Kserver+.pem", "rb").read()
        # ka_public = load_pem_public_key(encoded_key)
        encoded_key = open("Kserver-.pem", "rb").read()
        ka_private = load_pem_private_key(encoded_key, password=pass_phrase)
        # create certificate
        certificate = x509.CertificateBuilder().subject_name(subject).issuer_name(subject).serial_number(
            x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow()).not_valid_after(
            # Our certificate will be valid for 10 days
            datetime.datetime.utcnow() + datetime.timedelta(days=10)).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
            critical=False, ).public_key(userKey).sign(ka_private, hashes.SHA256(), default_backend())
        f1 = open(f'certificate{username}.pem', 'wb')
        f1.write(certificate.public_bytes(serialization.Encoding.PEM))
        f1.close()
        return certificate.public_bytes(serialization.Encoding.PEM)

    def checkCertificate(self,client):
        cert = client['client'].recv(4096)
        LOGGER.info(f'Received cert from first user = {cert}')
        certificate = x509.load_pem_x509_certificate(cert)
        pass_phrase = "SECURITY_HW_1".encode()
        f = open(f'Kserver-.pem', 'rb')
        cert_data = f.read()
        loaded = load_pem_private_key(data=cert_data, password=pass_phrase)

        public_key = loaded.public_key()

        try:
            verifier = public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                certificate.signature_hash_algorithm)
            LOGGER.info("Cert Valid")
            client['client'].send(bytes('pass', 'utf-8'))
            # return 'pass'
        except:
            LOGGER.error("Cert Invalid")
            client['client'].send('error in check')
            raise ValueError('Invalid Cert')
            # return 'wrong'


def main():
    server = Server()
    while True:
        server.TCPConnection()


main()
