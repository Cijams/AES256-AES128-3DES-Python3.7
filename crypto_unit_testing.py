import unittest
import cryptomanager


class MyTestCase(unittest.TestCase):
    def setUp(self):
        # Create and ensure the unencrypted text is correct.
        unencrypted_text = b'This is a test string'
        self.assertIsNotNone(unencrypted_text)
        print(unencrypted_text)

        # Create master encryption keys
        master_key_256 = cryptomanager.generate_master_key(1)
        master_key_512 = cryptomanager.generate_master_key(2)
        self.assertEqual(32, len(master_key_256))
        self.assertEqual(64, len(master_key_512))

        print("Master key 256:")
        print(master_key_256)
        print()

        print("Master key 512:")
        print(master_key_512)
        print()

        # Ensure key generated with the sha512 key is greater than the 256 key.
        print(self.assertGreater(len(master_key_512), len(master_key_256)))

    def test_something(self):

        self.assertEqual(True, True)
        unencrypted_text = b'This is a test string'
        print("\nUnencrypted text:")
        print(unencrypted_text.decode())
        print()
        cryptomanager.decrypt()
        print("I RAN")


if __name__ == '__main__':
    unittest.main()

