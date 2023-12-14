#!/usr/bin/python3
from getpass import getpass
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet, InvalidToken
import base64

with open("data.txt") as file:
    salt, cyphertext = file.read().split('=', maxsplit=1)

salt = base64.b64decode(salt+'=')

while True:
    password = getpass("Backup key: ")
    keygen = Scrypt(salt=salt, length=32, n=2**21, r=8, p=1)
    key = keygen.derive(bytes(password, 'utf8'))
    crypt = Fernet(base64.b64encode(key))
    
    try:
        plaintext = crypt.decrypt(cyphertext)
        break
    except InvalidToken:
        pass

data = list(zip(*(plaintext.decode('utf8').split('\0')[i::3] for i in range(3))))
print(data)

