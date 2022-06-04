import threading
from threading import Thread
from tkinter import *
import socket
import json
import logging
import colorama

from p2pChat.CustomFormatter import CustomFormatter

LOG_PATH = 'p2pChat/logs'
LOG_FILE_NAME = 'client'
logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
LOGGER = logging.getLogger("SECURITY")

fileHandler = logging.FileHandler("{0}/{1}.log".format(LOG_PATH, LOG_FILE_NAME))
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

SYMMETRIC_AES_KEY = 'a'
HASH_KEY = 'a'
IV = 'a'
NONCE = 'a'
MASTER_SECRET = "SECURITY_HW_1"


# key_128 = scrypt(pass_phrase, salt, 16, N=2 ** 14, r=8, p=1)

def set_var(Key=None, hash_key=None, iv=None, nonce=None, master_secret=None):
    if Key is not None:
        SYMMETRIC_AES_KEY = Key
    if hash_key is not None:
        HASH_KEY = hash_key
    if iv is not None:
        IV = iv
    if nonce is not None:
        NONCE = nonce
    if master_secret is not None:
        MASTER_SECRET = master_secret


def generate_mac(data, key):
    LOGGER.info('Generating mac')
    LOGGER.debug(f'MAC key ={key}')
    mac = Poly1305.new(key=key, cipher=AES, data=data, nonce=NONCE)

    return mac.hexdigest(), mac.nonce


def verify_mac(data, key, nonce, mac_digest):
    LOGGER.info("MAC verifying")
    mac_verify = Poly1305.new(data=data, key=key, nonce=nonce,
                              cipher=AES)
    try:
        mac_verify.hexverify(mac_digest)
        LOGGER.info('Message Authentication Success')
    except:
        LOGGER.error("Message Authentication Failed")


def encrypt_msg(data):
    LOGGER.info(f'Encrypting data = {data}')
    aes = AES.new(SYMMETRIC_AES_KEY, AES.MODE_CBC, IV)
    encrypted_data = aes.encrypt(pad(data, AES.block_size))
    digest, poly_nonce = generate_mac(data, HASH_KEY)
    return encrypted_data, digest,


def decrypt_msg(digest, encrypted_data):
    LOGGER.info(f'Decrypting data {encrypted_data}')
    aes_dec = AES.new(SYMMETRIC_AES_KEY, AES.MODE_CBC, IV)
    # VERIFY --------------------------------------------------------------------------------------
    msg = unpad(aes_dec.decrypt(encrypted_data), AES.block_size)
    LOGGER.info(f'Message = {msg}')
    verify_mac(msg, HASH_KEY, NONCE, digest)
    return msg
