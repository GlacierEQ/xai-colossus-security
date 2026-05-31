import unittest
import os
from src.crypto.engine import ApexCryptoEngine

class TestApexCrypto(unittest.TestCase):
    def setUp(self):
        self.key = os.urandom(32)
        self.engine = ApexCryptoEngine(self.key)

    def test_encrypt_decrypt(self):
        secret = b"Grok-5-Weights-Final"
        encrypted = self.engine.encrypt_data(secret)
        decrypted = self.engine.decrypt_data(encrypted)
        self.assertEqual(secret, decrypted)

if __name__ == '__main__':
    unittest.main()
