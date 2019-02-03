import unittest
import pyCryptoFrost
from binascii import hexlify
from binascii import unhexlify


class MyTestCase(unittest.TestCase):
    master_key_256 = ""
    master_key_512 = ""

    def setUp(self):
        """
         Generate unencrypted text and master keys
        """
        MyTestCase.master_key_256 = pyCryptoFrost.generate_master_key('sha256')
        MyTestCase.master_key_512 = pyCryptoFrost.generate_master_key('sha512')

    def test_master_keys(self):
        """
          Generate and test master keys
         """
        # test keys are correct sizes
        self.assertEqual(32, len(MyTestCase.master_key_256))
        self.assertEqual(64, len(MyTestCase.master_key_512))
        self.assertGreater(len(MyTestCase.master_key_512), len(MyTestCase.master_key_256))
        print("\nMaster encryption keys:\n256:")
        print(hexlify(MyTestCase.master_key_256).decode())
        print("512:")
        print(hexlify(MyTestCase.master_key_512).decode())
        print()
        print("Expected TypeError:")
        self.assertRaises(TypeError, (pyCryptoFrost.generate_master_key(1)))

        # Test keys for uniqueness.
        for i in range(0, 3):
            master_key_256 = pyCryptoFrost.generate_master_key('sha256')
            master_key_512 = pyCryptoFrost.generate_master_key('sha512')
            master_key_256_next = pyCryptoFrost.generate_master_key('sha256')
            master_key_512_next = pyCryptoFrost.generate_master_key('sha512')
            self.assertNotEqual(master_key_256, master_key_256_next)
            self.assertNotEqual(master_key_512, master_key_512_next)

    def test_generate_encryption_key(self):
        """
          Generate and test derived encryption keys
         """
        # derived keys for sha256
        key_length = 16
        master_key = pyCryptoFrost.generate_master_key('sha256')
        key256 = pyCryptoFrost.generate_encryption_key('sha256', master_key)
        print("\nDerived encryption key sha256:")
        print(hexlify(key256).decode())
        self.assertEqual(key_length, len(key256))

        # derived keys for sha512
        key_length = 32
        master_key = pyCryptoFrost.generate_master_key('sha512')
        key512 = pyCryptoFrost.generate_encryption_key('sha256', master_key)
        print("\nDerived encryption key sha512:")
        print(hexlify(key512).decode())
        self.assertEqual(key_length, len(key512))

        # Test key differences
        self.assertNotEqual(key256, key512)
        self.assertGreater(len(key512), len(key256))

    def test_generate_hmac_key(self):
        """
          Generate and test derived HMAC keys
         """
        # derived keys for sha256
        key_length = 16
        master_key = pyCryptoFrost.generate_master_key('sha256')
        key256 = pyCryptoFrost.generate_hmac_key(key_length, master_key)
        print("\nDerived HMAC key sha256:")
        print(hexlify(key256).decode())
        self.assertEqual(key_length, len(key256))

        # derived keys for sha512
        key_length = 32
        master_key = pyCryptoFrost.generate_master_key('sha512')
        key512 = pyCryptoFrost.generate_hmac_key(key_length, master_key)
        print("\nDerived HMAC key sha512:")
        print(hexlify(key512).decode())
        self.assertEqual(key_length, len(key512))

        # Test key differences
        self.assertNotEqual(key256, key512)
        self.assertGreater(len(key512), len(key256))

    def test_generate_iv(self):
        """
          Generate and test injection vectors
         """
        iv16 = pyCryptoFrost.generate_iv(16)
        print("\nIV 16:")
        print(hexlify(iv16).decode())

        iv32 = pyCryptoFrost.generate_iv(32)
        print("IV 32:")
        print(hexlify(iv32).decode())

        iv56 = pyCryptoFrost.generate_iv(56)
        print("IV 56:")
        print(hexlify(iv56).decode())

        # Ensure correct sizes and unique number generation
        self.assertGreater(len(iv32), len(iv16))
        self.assertGreater(len(iv56), len(iv32))
        self.assertNotEqual(iv16, pyCryptoFrost.generate_iv(16))
        self.assertNotEqual(iv32, pyCryptoFrost.generate_iv(32))
        self.assertNotEqual(iv56, pyCryptoFrost.generate_iv(56))

    def test_encrypt_aes128(self):
        r = b'**ENCRYPT ME**'

        master_key = pyCryptoFrost.generate_master_key('sha256')
        key256 = pyCryptoFrost.generate_hmac_key(16, master_key)
        pyCryptoFrost.encrypt_aes128(r, key256)

    def test_encrypt_aes256(self):
        print("stub")

    def test_encrypt_3des(self):
        print("stub")

    def test_generate_hmac(self):
        print("stub")

    def test_decrypt(self):
        pyCryptoFrost.decrypt()


if __name__ == '__main__':
    MyTestCase()

