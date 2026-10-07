"""Run real two-way cross tests and brute-force/collision experiments."""

import argparse
import csv
import hashlib
import json
import platform
import random
import shutil
import subprocess
import sys
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import reference_sdes as implementation_b
import sdes as implementation_a
from cryptanalysis import analyze_all_plaintexts, analyze_plaintext_collisions, brute_force_keys

ROOT = Path(__file__).resolve().parent
SHANGHAI = timezone(timedelta(hours=8))


def run_cross_tests(source: Path, output_directory: Path) -> dict:
    with source.open(encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        fields = list(reader.fieldnames or [])
        required = {"case_id", "key", "plaintext", "expected_ciphertext", "expected_decrypted_plaintext"}
        if not required <= set(fields) or len(fields) != len(set(fields)):
            raise ValueError("CSV must have unique columns and the five vector input columns")
        vectors = list(reader)
    if not vectors or any(None in row or None in row.values() for row in vectors):
        raise ValueError("CSV has no vectors or inconsistent column counts")
    cases = []
    for vector in vectors:
        key, plaintext = vector["key"], vector["plaintext"]
        a_cipher = implementation_a.encrypt_block(plaintext, key)
        b_plain = implementation_b.decrypt_block(a_cipher, key)
        b_cipher = implementation_b.encrypt_block(plaintext, key)
        a_plain = implementation_a.decrypt_block(b_cipher, key)
        a_to_b = a_cipher == vector["expected_ciphertext"] and b_plain == plaintext
        b_to_a = b_cipher == vector["expected_ciphertext"] and a_plain == plaintext
        passed = (a_to_b and b_to_a and a_cipher == b_cipher
                  and vector["expected_decrypted_plaintext"] == plaintext)
        cases.append(dict(vector, partner_ciphertext=b_cipher, partner_decrypted_plaintext=b_plain,
                          a_ciphertext=a_cipher, b_decrypted_plaintext=b_plain,
                          b_ciphertext=b_cipher, a_decrypted_plaintext=a_plain,
                          a_to_b_status="PASS" if a_to_b else "FAIL",
                          b_to_a_status="PASS" if b_to_a else "FAIL",
                          status="PASS" if passed else "FAIL"))
    output_directory.mkdir(parents=True, exist_ok=True)
    with (output_directory / "cross_test_results.csv").open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(cases[0]))
        writer.writeheader()
        writer.writerows(cases)
    return {"passed": all(case["status"] == "PASS" for case in cases), "cases": cases,
            "execution_scope": "A and independent B executed locally on the same computer",
            "human_partner_rerun_confirmed": False}


def analyze_random_sample(plaintext: str, key: str) -> dict:
    ciphertext = implementation_a.encrypt_block(plaintext, key)
    search = brute_force_keys(((plaintext, ciphertext),))
    verified = key in search.candidate_keys and all(
        implementation_b.encrypt_block(plaintext, candidate) == ciphertext
        and implementation_b.decrypt_block(ciphertext, candidate) == plaintext
        for candidate in search.candidate_keys)
    if not verified:
        raise RuntimeError("B did not verify the original key or every candidate")
    collisions = analyze_plaintext_collisions(plaintext)
    return {"plaintext": plaintext, "original_key": key, "ciphertext": ciphertext,
            "candidate_count": len(search.candidate_keys), "search": asdict(search),
            "candidates_verified_by_b": verified,
            "fixed_plaintext_analysis": {
                "distinct_ciphertexts": collisions.distinct_ciphertexts,
                "ciphertexts_with_multiple_keys": collisions.ciphertexts_with_multiple_keys,
                "maximum_keys_for_ciphertext": collisions.maximum_keys_for_ciphertext}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--fill-vectors", action="store_true", help="copy measured results back to the input CSV")
    arguments = parser.parse_args()
    now = datetime.now(SHANGHAI)
    output = arguments.output_dir or ROOT / "artifacts" / now.strftime("run_%Y%m%d_%H%M%S_%f")
    output = output.resolve()
    output_names = ("input_vectors.csv", "cross_test_results.csv", "random_input.json", "experiment_results.json")
    if any((output / name).exists() for name in output_names):
        parser.error("output directory contains an earlier experiment; choose a new directory")
    output.mkdir(parents=True, exist_ok=True)
    source = ROOT / "cross_test_vectors.csv"
    shutil.copyfile(source, output / "input_vectors.csv")
    generator = random.SystemRandom()
    sample = {"plaintext": format(generator.randrange(256), "08b"),
              "key": format(generator.randrange(1024), "010b"),
              "selection_method": "one SystemRandom draw for each value; no sample selection by outcome",
              "selected_at": now.isoformat(timespec="milliseconds")}
    # Save the draw before encryption/search so it cannot be silently selected by outcome.
    (output / "random_input.json").write_text(json.dumps(sample, indent=2), encoding="utf-8")
    cross = run_cross_tests(source, output)
    random_result = analyze_random_sample(sample["plaintext"], sample["key"])
    single = brute_force_keys((("10101010", "10001101"),))
    multiple = brute_force_keys((("10101010", "10001101"), ("00000000", "00001110")))
    full = analyze_all_plaintexts()
    hashes = {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
              for name in ("sdes.py", "reference_sdes.py", "cryptanalysis.py", "run_experiments.py")}
    revision = None
    if shutil.which("git"):
        git_result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True)
        revision = git_result.stdout.strip() if git_result.returncode == 0 else None
    results = {"started_at": now.isoformat(timespec="milliseconds"),
               "finished_at": datetime.now(SHANGHAI).isoformat(timespec="milliseconds"),
               "timezone": "Asia/Shanghai", "python": sys.version,
               "platform": platform.platform(), "python_executable": sys.executable,
               "source_repository": "https://github.com/kunyi39/sdes-information-security",
               "source_revision": revision,
               "implementation_sha256": hashes, "cross_test": cross,
               "single_pair_search": asdict(single), "multiple_pair_search": asdict(multiple),
               "random_sample": random_result, "all_plaintexts": asdict(full)}
    (output / "experiment_results.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    if arguments.fill_vectors:
        shutil.copyfile(output / "cross_test_results.csv", source)
    print(f"Cross tests: {sum(row['status'] == 'PASS' for row in cross['cases'])}/{len(cross['cases'])}")
    print(f"Random P={sample['plaintext']} K={sample['key']} C={random_result['ciphertext']}")
    print(f"Random candidate keys: {random_result['candidate_count']}; checked: 1024")
    print(f"All plaintexts with collisions: {full.plaintexts_with_collisions}/256")
    print(f"Evidence: {output}")
    return 0 if cross["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
