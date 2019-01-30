# AES256-AES128-3DES-Python3.7
Basic command line interface implementation of three popular encryption algorithms in Python.
Used to demonstrate round trip encryption to and from a file.


Chritopher Ijams
2019 January 26th
#
#   Christopher Ijams 2019
#
#   CryptoManager.py : Encryption implementation for files.
#
# ===========================================================================
#
#    TO USE: Ensure message to be encrypted is local to CryptoManager.py
#  as "plaintext.txt". Run Encryption. For decryption, program will detect
#  what algorithm was used to encrypt with. If it is AES128, AES256, or 3DES
#  it will attempt to decrypted it. Metadata for encryption serialized with pickle
#  and stored as stored as keys.pkl locally. HMAC Generated and checked locally
#  to ensure no text alterations have occurred.
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
