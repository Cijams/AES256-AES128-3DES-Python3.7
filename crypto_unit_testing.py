import unittest
import cryptomanager


class MyTestCase(unittest.TestCase):
    master_key_256 = ""
    master_key_512 = ""

    def setUp(self):
        """
         Generate unencrypted text and master keys
        """
        MyTestCase.master_key_256 = cryptomanager.generate_master_key(1)
        MyTestCase.master_key_512 = cryptomanager.generate_master_key(2)

    def test_master_keys(self):
        """
          Generate and test master keys
         """
        # test keys are correct sizes
        self.assertEqual(32, len(MyTestCase.master_key_256))
        self.assertEqual(64, len(MyTestCase.master_key_512))
        self.assertGreater(len(MyTestCase.master_key_512), len(MyTestCase.master_key_256))

        # Test keys for uniqueness.
        for i in range(0, 5):
            master_key_256 = cryptomanager.generate_master_key(1)
            master_key_512 = cryptomanager.generate_master_key(2)
            master_key_256_next = cryptomanager.generate_master_key(1)
            master_key_512_next = cryptomanager.generate_master_key(2)
            self.assertNotEqual(master_key_256, master_key_256_next)
            self.assertNotEqual(master_key_512, master_key_512_next)


if __name__ == '__main__':
    case = MyTestCase()
    case.setUp()
    case.test_master_keys()


