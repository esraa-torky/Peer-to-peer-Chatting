import logging
import colorama
from Crypto.PublicKey import RSA
from CustomFormatter import CustomFormatter

LOG_PATH = 'p2pChat/logs'
LOG_FILE_NAME = 'client'
logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
LOGGER = logging.getLogger("SECURITY")

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

colorama.init()
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import Poly1305
from Crypto.Protocol.KDF import scrypt

import time
class Key():
    def __int__(self):
        self.SYMMETRIC_AES_KEY = b'a'
        self.HASH_KEY = 'a'
        self.IV = b'a'
        self.NONCE = b'a'
        self.MASTER_SECRET = "SECURITY_HW_1"


    # key_128 = scrypt(pass_phrase, salt, 16, N=2 ** 14, r=8, p=1)

    def set_var(self,Key=None, hash_key=None, iv=None, nonce=None, master_secret=None):
        if Key is not None:
            self.SYMMETRIC_AES_KEY = Key
        if hash_key is not None:
            self.HASH_KEY = hash_key
        if iv is not None:
            self.IV = iv
        if nonce is not None:
            self.NONCE = nonce
        if master_secret is not None:
            self.MASTER_SECRET = master_secret
        LOGGER.info(f'Key={Key}, hash_key={hash_key}, iv={iv} len {len(iv)}, nonce={nonce}, master_secret={master_secret}')

    def generateRSAKeys(self,userName):
        pass_phrase = "SECURITY_HW_1"
        keys = RSA.generate(2048)
        public_key = keys.public_key()
        # exporting the public key
        f1 = open(f"K{userName}+.pem", 'wb')
        f1.write(public_key.export_key('PEM'))
        f1.close()
        # exporting the private key
        f2 = open(f'K{userName}-.pem', 'wb')
        f2.write(keys.export_key('PEM', pass_phrase))
        f2.close()

    def generate_mac(self,data, key):
        LOGGER.info('Generating mac')
        LOGGER.debug(f'MAC key ={key}')
        LOGGER.info(f"nonce is {self.NONCE} type {type(self.NONCE)}")
        mac = Poly1305.new(key=key, cipher=AES, data=bytes(data,'utf-8'), nonce=self.NONCE)

        return mac.hexdigest(), mac.nonce


    def verify_mac(self,data, key, nonce, mac_digest):
        LOGGER.info("MAC verifying")
        LOGGER.info(f'data is {data} type {type(data)}')
        dataA=bytearray()
        mac_verify = Poly1305.new(data=data, key=key, nonce= bytes (nonce,'utf-8'),
                                  cipher=AES)
        try:
            mac_verify.hexverify(mac_digest)
            LOGGER.info('Message Authentication Success')
        except:
            LOGGER.error("Message Authentication Failed")


    def encrypt_msg(self,data):
        LOGGER.info(f'Encrypting data = {data}')
        aes = AES.new(self.SYMMETRIC_AES_KEY, AES.MODE_CBC, self.IV)

        encrypted_data = aes.encrypt(pad(data.encode(), AES.block_size))
        digest, poly_nonce = self.generate_mac(data, self.HASH_KEY)
        return encrypted_data, digest,


    def decrypt_msg(self,digest, encrypted_data):
        LOGGER.info(f'Decrypting data {encrypted_data}')
        aes_dec = AES.new(self.SYMMETRIC_AES_KEY, AES.MODE_CBC, self.IV)
        # VERIFY --------------------------------------------------------------------------------------
        msg = unpad(aes_dec.decrypt(encrypted_data), AES.block_size)
        LOGGER.info(f'Message = {msg}')
        self.verify_mac(msg,self.HASH_KEY, self.NONCE, digest)
        return msg
