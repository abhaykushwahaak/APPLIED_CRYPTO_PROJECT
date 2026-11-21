import unittest

from Crypto.Cipher import ARC4
from rc4_crypto import encrypt_message, decrypt_message


class RC4ProjectTests(unittest.TestCase):
    def test_rc4_known_vector(self):
        # Standard RC4 test vector: Key / Plaintext -> BBF316E8D940AF0AD3
        result = ARC4.new(b"Key").encrypt(b"Plaintext").hex().upper()
        self.assertEqual(result, "BBF316E8D940AF0AD3")

    def test_round_trip(self):
        original = "Hello! RC4 communication test 🔐"
        envelope = encrypt_message(original, "correct horse battery staple")
        self.assertEqual(
            decrypt_message(envelope, "correct horse battery staple"), original
        )

    def test_wrong_password_rejected(self):
        envelope = encrypt_message("secret message", "password-one")
        with self.assertRaises(ValueError):
            decrypt_message(envelope, "password-two")

    def test_tampering_rejected(self):
        envelope = encrypt_message("do not modify", "shared-password")
        envelope["ciphertext"] = envelope["ciphertext"][:-4] + "AAAA"
        with self.assertRaises(ValueError):
            decrypt_message(envelope, "shared-password")


if __name__ == "__main__":
    unittest.main()
