import hashlib
import hmac
import Crypto
import Crypto.Cipher.AES
import Crypto.Util.Padding
import secrets
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
from binascii import hexlify
from binascii import unhexlify
from pyDes import *

"""
 This program uses a string to demonstrate a round-trip encryption/decryption
of 3DES, AES128 and AES256, to and from a text file.

 Initial creation of a master key is done using PBKDF#2.
User is allowed to select either sha256 or sha512. 100,000 iterations and a long
password were chosen to prevent cracking.

 Both the encryption key and hmac key are derived from the master key using PBKDF#2
and 1 iteration. Salt values are dynamically created using proven cryptographic libraries.

 Encryption algorithms are implemented using CBC chaining mode. IV's are randomly generated
and one block in length, adjusting size to the chosen algorithm.

 Python was chosen due to strong cryptographic support via libraries, and intuitive data
conversion.
"""


def generate_master_key(i):
    # Creation of master key using PBKDF#2 hashed with either SHA256 or SHA512.
    # Salt is a randomly generated 16 characters in hex format.

    salt = str.encode(secrets.token_hex(8))
    if i == 1:
        key = hashlib.pbkdf2_hmac('sha256', b'>>$$MasterPassword9000$$<<', salt, 100000)
    else:
        key = hashlib.pbkdf2_hmac('sha512', b'>>$$MasterPassword9000$$<<', salt, 100000)
    return key


def generate_encryption_key(key_length=16):
    # Derivation of encryption key using PBKDF#2
    # Hashed with sha256 and randomly generated salt.

    salt = str.encode(secrets.token_hex(8))
    key = hashlib.pbkdf2_hmac('sha256', master_key, salt, 1, key_length)
    return key


def generate_hmac(data="123"):
    # Creation of HMAC. IV + encrypted data

    return hmac.new(hmac_key, data, hashlib.sha256).hexdigest()


def hmac_key(key_length=16):
    # Derivation of HMAC key using PBKDF#2
    # Hashed with sha256 and randomly generated salt.

    salt = str.encode(secrets.token_hex(8))
    key = hashlib.pbkdf2_hmac('sha256', master_key, salt, 1, key_length)
    return key


def hash_select():
    # Obtain user selection for desired hash algorithm
    # to be used with the generation of the master key

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
    # Obtain user selection for desired algorithm

    print("Please select which algorithm you would like to use:")
    print("1. 3des")
    print("2. aes128")
    print("3. aes256")
    print()
    print("4. aes128 verbose")
    while True:
        try:
            i = int(input())
            if i == 1 or i == 2\
                    or i == 3 or i == 4:
                break
            print('Enter 1, 2, 3 or 4')
        except ValueError:
            print('Enter 1, 2, 3 or 4')
            continue
    if i == 1:
        encrypt_3des()
    if i == 2:
        encrypt_aes128()
    if i == 3:
        encrypt_aes256()
    if i == 4:
        encrypt_aes128_verbose()


def generate_iv(block_size=56):
    # Generated random bytes of various block size
    # to be used as an IV.

    return get_random_bytes(block_size)


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
    temp = ciphertext+iv
    local_hmac = generate_hmac(temp)
    print("\nEncrypted:")
    print(ciphertext)
    print("\nHMAC:\n" + local_hmac)
    del ciphertext

    # Opening file and decrypting data.
    f = open("encrypted.txt", "r")
    ciphertext = f.read().encode("utf-8")
    decipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    plaintext = decipher.decrypt(unhexlify(ciphertext))
    plaintext = Crypto.Util.Padding.unpad(plaintext, block_size, style='pkcs7')
    print("\nDecrypted:")
    print(plaintext.decode())


def encrypt_aes256():
    # Implementation of AES256.
    # Block size of 32 with PKCS7 padding.
    # Encrypts and message using AES256 to a file,
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
    temp = ciphertext + iv
    local_hmac = generate_hmac(temp)
    print("\nEncrypted:")
    print(ciphertext)
    print("\nHMAC:\n" + local_hmac)
    del ciphertext

    # Opening file and decrypting data.
    f = open("encrypted.txt", "r")
    ciphertext = f.read().encode("utf-8")
    decipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    plaintext = decipher.decrypt(unhexlify(ciphertext))
    plaintext = Crypto.Util.Padding.unpad(plaintext, block_size, style='pkcs7')
    print("\nDecrypted:")
    print(plaintext.decode())


def encrypt_3des():
    # Implementation of 3DES.
    # Block size of 16 with PKCS7 Padding.

    # Initial set up
    block_size = 16
    iv = generate_iv(8)
    encryption_key = generate_encryption_key(block_size)
    plaintext = b'THIS IS THE DATA THAT IS GOING TO BE ENCRYPTED'
    print(plaintext.decode())
    plaintext = Crypto.Util.Padding.pad(plaintext, block_size, style='pkcs7')

    # Encryption to file using 3des, CBC
    cipher = triple_des(encryption_key, CBC, iv, pad=None)
    ciphertext = cipher.encrypt(plaintext)
    f = open("encrypted.txt", "wb")
    f.write(hexlify(ciphertext))
    temp = ciphertext + iv
    local_hmac = generate_hmac(temp)
    print("\nRaw encrypted:")
    print(ciphertext)
    print("\nHex:")
    print(hexlify(ciphertext))

    # Opening file and retrieving encrypted content
    f = open("encrypted.txt", "r")
    ciphertext = f.read().encode("utf-8")
    print("\nHMAC IS:\n" + local_hmac)
    print("\nDecrypted and decoded:")

    # Decryption
    plaintext = cipher.decrypt(unhexlify(ciphertext))
    plaintext = Crypto.Util.Padding.unpad(plaintext, block_size, style='pkcs7')
    print(plaintext.decode())


def encrypt_aes128_verbose():
    # VERBOSE IMPLEMENTATION FOR DEMO PURPOSES

    print()
    print("ROUND TRIP PRINTED:\n")
    block_size = 16
    encryption_key = generate_encryption_key(block_size)
    iv = generate_iv(16)
    plaintext = b'**ENCRYPT ME**'

    print("Original text before pkcs7 padding is added:")
    print(plaintext.decode())

    plaintext = Crypto.Util.Padding.pad(plaintext, block_size, style='pkcs7')
    print("\nData encoded with utf-8 and padded with pkcs7:")
    print(plaintext)
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext)

    print("\nRaw Encrypted data:")
    print(ciphertext)
    print("\nConverted to hex and written to file:")
    print(hexlify(ciphertext))
    print()

    f = open("encrypted.txt", "wb")
    f.write(hexlify(ciphertext))
    del ciphertext

    f = open("encrypted.txt", "r")
    ciphertext = f.read().encode("utf-8")
    print("Text read from file:")
    print(ciphertext)

    decipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    plaintext = decipher.decrypt(unhexlify(ciphertext))

    print("\nText unencrypted with padding")
    print(plaintext)
    plaintext = Crypto.Util.Padding.unpad(plaintext, block_size, style='pkcs7')
    print("\nOriginal form:")
    print(plaintext.decode())


# Start
master_key = hash_select()
hmac_key = hmac_key()
algorithm_select()
