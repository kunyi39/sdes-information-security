"""Stage A checks for the S-DES core implementation."""

import unittest

from sdes import (
    EP,
    IP,
    IP_INV,
    LS1,
    LS2,
    P4,
    P8,
    P10,
    SBOX1,
    SBOX2,
    decrypt_block,
    decrypt_bytes,
    encrypt_block,
    encrypt_bytes,
    generate_subkeys,
)


class SDESCoreTests(unittest.TestCase):
    def test_assignment_parameters_and_reference_vector(self):
        # These values are copied from the assignment handout. This also
        # guards against accidentally replacing its modified SBox2.
        self.assertEqual(P10, (3, 5, 2, 7, 4, 10, 1, 9, 8, 6))
        self.assertEqual(P8, (6, 3, 7, 4, 8, 5, 10, 9))
        self.assertEqual(LS1, (2, 3, 4, 5, 1))
        self.assertEqual(LS2, (3, 4, 5, 1, 2))
        self.assertEqual(IP, (2, 6, 3, 1, 4, 8, 5, 7))
        self.assertEqual(IP_INV, (4, 1, 3, 5, 7, 2, 8, 6))
        self.assertEqual(EP, (4, 1, 2, 3, 2, 3, 4, 1))
        self.assertEqual(P4, (2, 4, 3, 1))
        self.assertEqual(
            SBOX1,
            ((1, 0, 3, 2), (3, 2, 1, 0), (0, 2, 1, 3), (3, 1, 0, 2)),
        )
        self.assertEqual(
            SBOX2,
            ((0, 1, 2, 3), (2, 3, 1, 0), (3, 0, 1, 2), (2, 1, 0, 3)),
        )

        # Fixed expected values for the assignment's parameter set:
        # key 1010000010 -> K1 10100100, K2 01000011
        # plaintext 10101010 -> ciphertext 10001101.
        self.assertEqual(generate_subkeys("1010000010"), ("10100100", "01000011"))
        self.assertEqual(encrypt_block("10101010", "1010000010"), "10001101")
        self.assertEqual(decrypt_block("10001101", "1010000010"), "10101010")

    def test_subkeys_are_eight_bits(self):
        key1, key2 = generate_subkeys("1010000010")
        self.assertEqual((len(key1), len(key2)), (8, 8))
        self.assertTrue(set(key1 + key2) <= {"0", "1"})

    def test_block_round_trip(self):
        plaintext = "10101010"
        key = "1010000010"
        ciphertext = encrypt_block(plaintext, key)
        self.assertEqual(len(ciphertext), 8)
        self.assertEqual(decrypt_block(ciphertext, key), plaintext)

    def test_all_byte_values_round_trip(self):
        key = "0111111101"
        original = bytes(range(256))
        encrypted = encrypt_bytes(original, key)
        self.assertEqual(len(encrypted), len(original))
        self.assertEqual(decrypt_bytes(encrypted, key), original)

    def test_invalid_inputs_are_rejected(self):
        with self.assertRaises(ValueError):
            encrypt_block("101", "1010000010")
        with self.assertRaises(ValueError):
            encrypt_block("10101010", "10100000x0")


if __name__ == "__main__":
    unittest.main(verbosity=2)
