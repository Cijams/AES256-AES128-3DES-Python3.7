import unittest
import cryptomanager


class MyTestCase(unittest.TestCase):
    def test_something(self):
        self.assertEqual(True, True)

        master_key = cryptomanager.generate_master_key(1)

        cryptomanager.decrypt()


if __name__ == '__main__':
    unittest.main()

    print("k")
