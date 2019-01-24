from Crypto.Random import get_random_bytes
from pyDes import *
import hashlib
import hmac
import Crypto
import Crypto.Cipher.AES
from Crypto.Cipher import AES
import Crypto.Cipher.AES
import Crypto.Util.Padding
from binascii import hexlify, unhexlify


def generate_master_key(i):  # Creation of the master key using PBKDF#2 with sha512
    if i == 1:
        key = hashlib.pbkdf2_hmac('sha256', b'>>$$MasterPassword9000$$<<', b'A_g00d_SaLt', 100000)
    else:
        key = hashlib.pbkdf2_hmac('sha512', b'>>$$MasterPassword9000$$<<', b'A_g00d_SaLt', 100000)
    return key  # if trouble, use binary.hexlify


def generate_encryption_key(key_length=16):
    key = hashlib.pbkdf2_hmac('sha256', master_key, b'An_EvEn_Better_SalT', 1, key_length)
    return key


def hmac_key(key_length=16):
    key = hashlib.pbkdf2_hmac('sha256', master_key, b'A_DiffereNT_SalT', 1, key_length)
    return key


def hash_select():  # Get user selection for desired hash algorithm
    print('Would you like to use sha256 or sha512?')
    print('1. sha256')
    print('2. sha512')
    while True:
        try:
            i = int(input())
            if i == 1:
                break
            if i == 2:
                break
            print('Enter 1 or 2.')
        except ValueError:
            print("Please enter 1 or 2")
            continue
    key = ""
    if i == 1:
        key = generate_master_key(1)
    if i == 2:
        key = generate_master_key(2)
    return key


def algorithm_select():
    print("Please select which algorithm you would like to use")
    print("1. 3des")
    print("2. aes128")
    print("3. aes256")
    while True:
        try:
            i = int(input())
            if i == 1:
                break
            if i == 2:
                break
            if i == 3:
                break
            print('Enter 1, 2 or 3')
        except ValueError:
            print("Please enter 1, 2 or 3")
            continue
    if i == 1:
        encrypt_3des()

    if i == 2:
        encrypt_aes128()

    if i == 3:
        encrypt_aes256()


def generate_iv(block_size=56):
    return get_random_bytes(block_size)


def encrypt_3des():  # Implementation of 3des
    block_size = 16  # Block size of 64 bits for 3des
    encryption_key = generate_encryption_key(block_size)
    data = "This is my encrypted data"
    cipher = triple_des(encryption_key, CBC, generate_iv(8), pad=None, padmode=PAD_PKCS5)
    encrypted_information = cipher.encrypt(data)
    print("Encrypted: %r" % encrypted_information)
    print("Decrypted: %r" % cipher.decrypt(encrypted_information))


def encrypt_aes128():
    # Implementation of AES128.
    # Block size of 16 with PKCS7 padding.
    # Encrypts and message using AES128 to a file,
    # and reads it back to decrypt the data.

    # Initial set up of encryption cipher.
    block_size = 16
    encryption_key = generate_encryption_key(block_size)
    iv = generate_iv(block_size)
    plaintext = b'THIS IS THE DATA THAT IS GOING TO BE ENCRYPTED'
    print(plaintext.decode())
    plaintext = Crypto.Util.Padding.pad(plaintext, block_size, style='pkcs7')
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)

    # Encryption of data and writing to file.
    ciphertext = cipher.encrypt(plaintext)
    f = open("encrypted.txt", "wb")
    f.write(hexlify(ciphertext))
    print(ciphertext)
    del ciphertext

    # Opening file and decrypting data.
    f = open("encrypted.txt", "r")
    ciphertext = f.read().encode("utf-8")
    decipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    plaintext = decipher.decrypt(unhexlify(ciphertext))
    plaintext = Crypto.Util.Padding.unpad(plaintext, block_size, style='pkcs7')
    print(plaintext.decode())


def encrypt_aes256():
    # Implementation of AES128.
    # Block size of 16 with PKCS7 padding.
    # Encrypts and message using AES128 to a file,
    # and reads it back to decrypt the data.

    # Initial set up of encryption cipher.
    block_size = 32
    encryption_key = generate_encryption_key(block_size)
    iv = generate_iv(16)
    plaintext = b'THIS IS THE DATA THAT IS GOING TO BE ENCRYPTED'
    print(plaintext.decode())
    plaintext = Crypto.Util.Padding.pad(plaintext, block_size, style='pkcs7')
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)

    # Encryption of data and writing to file.
    ciphertext = cipher.encrypt(plaintext)
    f = open("encrypted.txt", "wb")
    f.write(hexlify(ciphertext))
    print(ciphertext)
    del ciphertext

    # Opening file and decrypting data.
    f = open("encrypted.txt", "r")
    ciphertext = f.read().encode("utf-8")
    decipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    plaintext = decipher.decrypt(unhexlify(ciphertext))
    plaintext = Crypto.Util.Padding.unpad(plaintext, block_size, style='pkcs7')
    print(plaintext.decode())


def generate_hmac():
    return hmac.new(hmac_key, b'encrypted message here', hashlib.sha256).hexdigest()


def encrypt_aes128_verbose():  # VERBOSE IMPLEMENTATION FOR DEMO PURPOSES
    # REMOVE ME
    print()
    block_size = 16  # Block size of 128 bits for aes128.
    encryption_key = generate_encryption_key(block_size)
    iv = generate_iv(16)
    plaintext = b'ENCRYPT ME'

    print("Origional text before pkcs7 padding is added:")
    print(plaintext.decode())

    plaintext = Crypto.Util.Padding.pad(plaintext, block_size, style='pkcs7')
    print("\nThis is now the data encoded with utf-8 and padded with pkcs7")
    print(plaintext)
    print()
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)

    print("\nRaw Encrypted data:")
    print(ciphertext)
    print("Hex:")
    print(hexlify(ciphertext))
    print()

    f = open("text.txt", "wb")
    f.write(hexlify(ciphertext))
    f = open("text.txt", "r")

    temp = f.read().encode("utf-8")

    decipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    plaintext = decipher.decrypt(unhexlify(temp))

    print("Back to unencrypted with padding")
    print(plaintext)
    plaintext = Crypto.Util.Padding.unpad(plaintext, block_size, style='pkcs7')
    print("\noriginal form:")
    print(plaintext.decode())


# Start
master_key = hash_select()
hmac_key = hmac_key()
algorithm_select()

