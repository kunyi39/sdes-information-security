"""Checks for independent implementation and experiment evidence."""

import csv
import importlib
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def required_module(name):
    if importlib.util.find_spec(name) is None:
        raise AssertionError(f"Missing experiment implementation: {name}")
    return importlib.import_module(name)


class CooperationTests(unittest.TestCase):
    def test_csv_columns_and_leading_zeroes(self):
        with Path("cross_test_vectors.csv").open(encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.reader(handle))
        self.assertEqual(len(rows), 6)
        for row in rows[1:]:
            self.assertEqual(len(row), len(rows[0]))
        self.assertEqual(rows[2][2], "00000000")
        self.assertEqual(rows[4][1], "0000000000")

    def test_independent_implementation_matches_modified_sbox_vectors(self):
        reference = required_module("reference_sdes")
        vectors = (
            ("1010000010", "10101010", "10001101"),
            ("1010000010", "00000000", "00001110"),
            ("0111111101", "11010111", "00001011"),
            ("0000000000", "00000000", "11110000"),
            ("1111111111", "11111111", "00001111"),
        )
        self.assertEqual(reference.generate_subkeys("1010000010"), ("10100100", "01000011"))
        for key, plaintext, ciphertext in vectors:
            self.assertEqual(reference.encrypt_block(plaintext, key), ciphertext)
            self.assertEqual(reference.decrypt_block(ciphertext, key), plaintext)
        for value in range(256):
            plaintext = format(value, "08b")
            ciphertext = reference.encrypt_block(plaintext, "0111111101")
            self.assertEqual(reference.decrypt_block(ciphertext, "0111111101"), plaintext)

    def test_reference_rejects_invalid_blocks_and_keys(self):
        reference = required_module("reference_sdes")
        for plaintext, key in (("101", "1010000010"), ("1010101x", "1010000010"),
                               ("10101010", "10100000x0"), ("10101010", "")):
            with self.assertRaises(ValueError):
                reference.encrypt_block(plaintext, key)
        with self.assertRaises(TypeError):
            reference.decrypt_block(123, "1010000010")

    def test_cross_test_writes_actual_results_and_detects_wrong_expectations(self):
        experiments = required_module("run_experiments")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "vectors.csv"
            source.write_text(
                "case_id,key,plaintext,expected_ciphertext,expected_decrypted_plaintext\n"
                "1,1010000010,10101010,10001101,10101010\n", encoding="utf-8")
            result = experiments.run_cross_tests(source, root)
            self.assertTrue(result["passed"])
            row = result["cases"][0]
            self.assertEqual(row["a_ciphertext"], "10001101")
            self.assertEqual(row["b_decrypted_plaintext"], "10101010")
            self.assertEqual(row["b_ciphertext"], "10001101")
            self.assertEqual(row["a_decrypted_plaintext"], "10101010")
            self.assertEqual(row["status"], "PASS")
            with (root / "cross_test_results.csv").open(encoding="utf-8-sig", newline="") as handle:
                written = list(csv.DictReader(handle))
            self.assertEqual(written[0]["status"], "PASS")
            source.write_text(source.read_text().replace("10001101", "00000000"), encoding="utf-8")
            self.assertFalse(experiments.run_cross_tests(source, root)["passed"])

    def test_random_sample_preserves_original_key_and_all_candidates(self):
        experiments = required_module("run_experiments")
        result = experiments.analyze_random_sample("10101010", "1010000010")
        self.assertEqual(result["ciphertext"], "10001101")
        self.assertEqual(result["search"]["checked_keys"], 1024)
        self.assertIn("1010000010", result["search"]["candidate_keys"])
        self.assertEqual(result["candidate_count"], len(result["search"]["candidate_keys"]))
        self.assertTrue(result["candidates_verified_by_b"])

    def test_experiment_runs_on_python_only_machine_without_git(self):
        required_module("run_experiments")
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [sys.executable, "run_experiments.py", "--output-dir", temporary],
                env=dict(os.environ, PATH="", PYTHONUTF8="1"),
                capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((Path(temporary) / "experiment_results.json").is_file())

    def test_explicit_output_directory_preserves_existing_vector_file(self):
        required_module("run_experiments")
        with tempfile.TemporaryDirectory() as temporary:
            existing = Path(temporary) / "input_vectors.csv"
            existing.write_bytes(b"existing experiment input\n")
            result = subprocess.run(
                [sys.executable, "run_experiments.py", "--output-dir", temporary],
                env=dict(os.environ, PYTHONUTF8="1"),
                capture_output=True, text=True, encoding="utf-8")
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(existing.read_bytes(), b"existing experiment input\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
