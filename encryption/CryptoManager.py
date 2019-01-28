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
import pickle

#
#   Christopher Ijams 2019
#
#   CryptoManager.py : Encryption implementation for files
#
# ===========================================================================
#
#    TO USE: Ensure message to be encrypted is local to CryptoManager.py
#  as "plaintext.txt". Run Encryption. For decryption, program will detect
#  what algorithm was used to encrypt with. If it is AES128, AES256, or 3DES
#  it will attempt to decrypted it. Metadata for encryption serialized with pickle
#  and stored as stored as keys.pkl locally.
#
# ===========================================================================
#
#    This program demonstrates a round-trip encryption/decryption
#  of 3DES, AES128 and AES256, to and from a text file.
#
#    Initial creation of a master key is done using PBKDF#2.
#  User is allowed to select either sha256 or sha512. 100,000 iterations and a long
#  password were chosen to prevent cracking.
#
#    Both the encryption key and hmac key are derived from the master key using PBKDF#2
#  and 1 iteration. Salt values are dynamically created using proven cryptographic libraries.
#
#    Encryption algorithms are implemented using CBC chaining mode. IV's are randomly generated
#  and one block in length, adjusting size to the chosen algorithm.
#
#    Python was chosen due to strong cryptographic support via libraries, and intuitive data
#  conversion.


def generate_master_key(algorithm_choice):
    """Creation of master key using PBKDF#2 hashed with either SHA256 or SHA512.
    Salt is a randomly generated 16 characters in hex format.

    Args:
        algorithm_choice (integer):
            An integer who's value determines which algorithm is
            going to be used.

    Return:
        key (byte):
            The generated master key to be used for encryption and
            hashing derivation
    """
    salt = str.encode(secrets.token_hex(8))
    if algorithm_choice == 1:
        key = hashlib.pbkdf2_hmac('sha256', b'>>$$MasterPassword9000$$<<', salt, 100000)
    else:
        key = hashlib.pbkdf2_hmac('sha512', b'>>$$MasterPassword9000$$<<', salt, 100000)
    return key


def generate_encryption_key(key_length=16):
    """Derivation of encryption key using PBKDF#2
    Hashed with sha256 and randomly generated salt.

    Args:
        key_length (integer):
            Length of the key needed to be generated.
            accepts multiples of 16, expecting values
            of either 16 or 32.
    Return:
        key (byte):
            The encryption key for each algorithm.
    """
    salt = str.encode(secrets.token_hex(8))
    key = hashlib.pbkdf2_hmac('sha256', master_key, salt, 1, key_length)
    return key


def generate_hmac(data=b'123'):
    """Generate the HMAC.

    Args:
        data (byte):
            The cipher text to be hashed. Default data
            to prevent errors.
    Return:
        HMAC (byte):
            The HMAC of the cipher text.
    """

    return hmac.new(hmac_key, data, hashlib.sha256).hexdigest()


def hmac_key(key_length=16):
    """Derivation of HMAC key using PBKDF#2
    Hashed with SHA256 and randomly generated salt.
    
    Args:
        key_length (integer):
            Length of the key needed to be generated.
            accepts multiples of 16, expecting values
            of either 16 or 32.
    Return:
        key (byte):
            The hmac key
    """
    salt = str.encode(secrets.token_hex(8))
    key = hashlib.pbkdf2_hmac('sha256', master_key, salt, 1, key_length)
    return key


def hash_select():
    """

    Args:

    Return:

    """
    # Obtain user selection for desired hash algorithm
    # to be used with the generation of the master key

    print('Would you like to use sha256 or sha512?')
    print('1. sha256')
    print('2. sha512')
    while True:
        try:
            hash_choice = int(input())
            if hash_choice == 1:
                break
            if hash_choice == 2:
                break
            print('Enter 1 or 2.')
        except ValueError:
            print("Please enter 1 or 2")
            continue
    key = ""
    if hash_choice == 1:
        key = generate_master_key(1)
    if hash_choice == 2:
        key = generate_master_key(2)
    return key


def generate_iv(block_size=56):
    """

    Args:

    Return:

    """
    # Generated random bytes of various block size
    # to be used as an IV.

    return get_random_bytes(block_size)


def encrypt_aes128(plaintext):
    """

    Args:

    Return:

    """
    # Implementation of AES128.
    # Block size of 16 with PKCS7 padding.
    # Encrypts and message using AES128 to a file,
    # and reads it back to decrypt the data.

    # Initial set up of encryption cipher.
    algorithm = "aes128"
    key_size = 16
    block_size = 16
    encryption_key = generate_encryption_key(key_size)
    iv = generate_iv(block_size)
    plaintext = Crypto.Util.Padding.pad(plaintext, block_size, style='pkcs7')
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)

    # Encryption of data and writing to file.
    ciphertext = cipher.encrypt(plaintext)
    f = open("encrypted.txt", "wb")
    f.write(hexlify(ciphertext))

    local_hmac = generate_hmac(ciphertext+iv)

    print("NOW ENCRYPTING:")
    print("\nHMAC:\n" + local_hmac)
    print("\nEncrypted:")
    print(ciphertext)
    del ciphertext

    local_keys = dict(int_list=[1, 2, 3, 4],
                      my_keys=encryption_key,
                      my_hmac=local_hmac,
                      my_iv=iv,
                      my_block_size=block_size,
                      my_algorithm=algorithm,
                      my_key_size=key_size)

    pickle.dump(local_keys, open('keys.pkl', 'wb'))


def decrypt_aes():
    """

    Args:

    Return:

    """
    # TODO generate HMAC INSTEAD OF READING IT

    # Initialize variables
    algorithm = "Unknown Algorithm"
    local_hmac = ""
    encryption_key = ""
    iv = ""
    block_size = ""

    # Read data and ensure it matches with decryption algorithm
    print("NOW DECRYPTING:")
    try:
        enc_meta = pickle.load(open('keys.pkl', 'rb'))
        encryption_key = enc_meta['my_keys']
        local_hmac = enc_meta['my_hmac']
        iv = enc_meta['my_iv']
        block_size = enc_meta['my_block_size']
        algorithm = enc_meta['my_algorithm']
    except (FileNotFoundError, RuntimeError):
        print("File format is incorrect. Encrypt the data using this program.")
    print(algorithm)
    if algorithm != "aes128" and algorithm != "aes256" and algorithm != "3des":
        print("Error trying to decrypt " + algorithm)
        sys.exit(0)

    # Verify HMAC and decrypt data
    print("\nHMAC:" + local_hmac)
    f = open("encrypted.txt", "r")
    ciphertext = f.read().encode("utf-8")
    if algorithm == "aes128" or algorithm == "aes256":
        decipher = AES.new(encryption_key, AES.MODE_CBC, iv)
    else:
        decipher = triple_des(encryption_key, CBC, iv, pad=None)
    plaintext = decipher.decrypt(unhexlify(ciphertext))

    plaintext = Crypto.Util.Padding.unpad(plaintext, block_size, style='pkcs7')
    print("\nDecrypted:")
    f = open("plaintext.txt", "w")
    f.write(plaintext.decode())
    print(plaintext.decode())


def encrypt_aes256(plaintext):
    """

    Args:

    Return:

    """
    # Implementation of AES128.
    # Block size of 16 with PKCS7 padding.
    # Encrypts and message using AES128 to a file,
    # and reads it back to decrypt the data.

    # Initial set up of encryption cipher.
    algorithm = "aes256"
    key_size = 32
    block_size = 16
    encryption_key = generate_encryption_key(key_size)
    iv = generate_iv(block_size)
    plaintext = Crypto.Util.Padding.pad(plaintext, block_size, style='pkcs7')
    cipher = AES.new(encryption_key, AES.MODE_CBC, iv)

    # Encryption of data and writing to file.
    ciphertext = cipher.encrypt(plaintext)
    f = open("encrypted.txt", "wb")
    f.write(hexlify(ciphertext))

    local_hmac = generate_hmac(ciphertext+iv)

    print("NOW ENCRYPTING:")
    print("\nHMAC:\n" + local_hmac)
    print("\nEncrypted:")
    print(ciphertext)
    del ciphertext

    local_keys = dict(int_list=[1, 2, 3, 4],
                      my_keys=encryption_key,
                      my_hmac=local_hmac,
                      my_iv=iv,
                      my_block_size=block_size,
                      my_algorithm=algorithm,
                      my_key_size=key_size)

    pickle.dump(local_keys, open('keys.pkl', 'wb'))


def encrypt_3des(plaintext):
    """

    Args:

    Return:

    """
    # Implementation of 3DES.
    # Block size of 16 with PKCS7 Padding.

    # Initial set up
    algorithm = "3des"
    key_size = 16
    block_size = 16
    iv = generate_iv(8)
    encryption_key = generate_encryption_key(block_size)
    print(plaintext.decode())
    plaintext = Crypto.Util.Padding.pad(plaintext, block_size, style='pkcs7')

    cipher = triple_des(encryption_key, CBC, iv, pad=None)
    ciphertext = cipher.encrypt(plaintext)
    f = open("encrypted.txt", "wb")
    f.write(hexlify(ciphertext))

    temp = ciphertext + iv
    local_hmac = generate_hmac(temp)

    print("NOW ENCRYPTING:")
    print("\nHMAC:\n" + local_hmac)
    print("\nEncrypted:")
    print(ciphertext)
    del ciphertext

    local_keys = dict(int_list=[1, 2, 3, 4],
                      my_keys=encryption_key,
                      my_hmac=local_hmac,
                      my_iv=iv,
                      my_block_size=block_size,
                      my_algorithm=algorithm,
                      my_key_size=key_size)

    pickle.dump(local_keys, open('keys.pkl', 'wb'))


def user_choice():
    """

    Args:

    Return:

    """
    print("\n\nWould you like to encrypt or decrypt?")
    print("1. Encrypt")
    print("2. Decrypt")
    i = get_int(1)
    if i == 1:
        return 1
    if i == 2:
        return 2


def get_int(self=1):
    """

    Args:

    Return:

    """
    while True:
        if self == 1:
            try:
                i = int(input())
                if i == 1 or i == 2:
                    break
                print('Enter 1 or 2')
            except ValueError:
                print('Enter 1 or 2')
                continue
        if self == 2:
            try:
                i = int(input())
                if i == 1 or i == 2 or i == 3:
                    break
                print('Enter 1, 2 or 3')
            except ValueError:
                print('Enter 1, 2 or 3')
                continue
    return i


# Start
choice = user_choice()
if choice == 1:
    try:
        unencrypted_text = (open('plaintext.txt', 'rb'))
        unencrypted_text = unencrypted_text.read()
        print()
        print("This is the plaintext to be encrypted:")
        print(unencrypted_text.decode())
        print()
    except FileNotFoundError:
        print("Ensure the text to be encrypted is in the local directory as \"plaintext.txt\"")
        sys.exit(0)
    master_key = hash_select()
    hmac_key = hmac_key()

    print("Please select which algorithm you would like to use:")
    print("1. 3des")
    print("2. aes128")
    print("3. aes256")
    print()
    alg = get_int(2)
    if alg == 1:
        encrypt_3des(unencrypted_text)
    if alg == 2:
        encrypt_aes128(unencrypted_text)
    else:
        encrypt_aes256(unencrypted_text)


if choice == 2:
    decrypt_aes()
