"""Tests for ASCII support, key search, and key-collision analysis."""

import unittest

from cryptanalysis import analyze_all_plaintexts, analyze_plaintext_collisions, brute_force_keys
from sdes import decrypt_text, encrypt_text


class ExtendedFeatureTests(unittest.TestCase):
    def test_ascii_text_round_trip(self):
        key = "1010000010"
        plaintext = "S-DES test 123!"
        ciphertext = encrypt_text(plaintext, key)
        self.assertTrue(all(character in "0123456789ABCDEF" for character in ciphertext))
        self.assertEqual(decrypt_text(ciphertext, key), plaintext)

    def test_empty_ascii_text_round_trip(self):
        self.assertEqual(encrypt_text("", "1010000010"), "")
        self.assertEqual(decrypt_text("", "1010000010"), "")

    def test_non_ascii_text_is_rejected(self):
        with self.assertRaises(ValueError):
            encrypt_text("中文", "1010000010")

    def test_brute_force_finds_key_and_uses_multiple_pairs(self):
        key = "1010000010"
        pairs = (("10101010", "10001101"), ("00000000", "00001110"))
        result = brute_force_keys(pairs)
        self.assertEqual(result.checked_keys, 1024)
        self.assertIn(key, result.candidate_keys)
        self.assertEqual(result.candidate_keys, ("1010000010", "1011001010"))
        self.assertTrue(result.started_at)
        self.assertTrue(result.finished_at)

    def test_fixed_plaintext_has_key_collisions(self):
        result = analyze_plaintext_collisions("10101010")
        self.assertEqual(sum(len(keys) for keys in result.collisions.values()),
                         1024 - result.distinct_ciphertexts + len(result.collisions))
        self.assertGreater(result.ciphertexts_with_multiple_keys, 0)
        self.assertGreater(result.maximum_keys_for_ciphertext, 1)

    def test_all_plaintexts_have_key_collisions(self):
        result = analyze_all_plaintexts()
        self.assertEqual(result.plaintext_blocks_checked, 256)
        self.assertEqual(result.keys_checked_per_plaintext, 1024)
        self.assertEqual(result.plaintexts_with_collisions, 256)


if __name__ == "__main__":
    unittest.main(verbosity=2)
