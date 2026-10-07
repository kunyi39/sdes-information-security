"""Exhaustive key search and key-collision analysis for S-DES."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from time import perf_counter
from typing import Iterable

from sdes import decrypt_block, encrypt_block


@dataclass(frozen=True)
class BruteForceResult:
    """Results and elapsed time for an exhaustive 10-bit key search."""

    candidate_keys: tuple[str, ...]
    checked_keys: int
    elapsed_seconds: float
    started_at: str
    finished_at: str


@dataclass(frozen=True)
class CollisionAnalysis:
    """Key-to-ciphertext distribution for one fixed plaintext block."""

    plaintext: str
    distinct_ciphertexts: int
    ciphertexts_with_multiple_keys: int
    maximum_keys_for_ciphertext: int
    collisions: dict[str, tuple[str, ...]]


@dataclass(frozen=True)
class FullPlaintextAnalysis:
    """Summary from checking every one of the 256 plaintext blocks."""

    plaintext_blocks_checked: int
    keys_checked_per_plaintext: int
    plaintexts_with_collisions: int
    minimum_distinct_ciphertexts: int
    maximum_distinct_ciphertexts: int


def _all_keys() -> Iterable[str]:
    for value in range(1 << 10):
        yield format(value, "010b")


def brute_force_keys(known_pairs: Iterable[tuple[str, str]]) -> BruteForceResult:
    """Find all 10-bit keys matching every (plaintext, ciphertext) pair.

    Each pair is supplied as two 8-bit binary strings. Multiple pairs help
    eliminate keys that happen to match a single pair.
    """
    pairs = tuple(known_pairs)
    if not pairs:
        raise ValueError("provide at least one plaintext/ciphertext pair")
    for plaintext, ciphertext in pairs:
        # The block routines perform exact type, length, and bit checks.
        decrypt_block(ciphertext, "0000000000")
        if len(plaintext) != 8 or any(bit not in "01" for bit in plaintext):
            raise ValueError("each plaintext must contain exactly 8 binary bits")

    started_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
    start = perf_counter()
    matches = []
    checked = 0
    for key in _all_keys():
        checked += 1
        if all(encrypt_block(plaintext, key) == ciphertext for plaintext, ciphertext in pairs):
            matches.append(key)
    elapsed = perf_counter() - start
    finished_at = datetime.now().astimezone().isoformat(timespec="milliseconds")
    return BruteForceResult(tuple(matches), checked, elapsed, started_at, finished_at)


def analyze_key_ambiguity(plaintext: str, ciphertext: str) -> tuple[str, ...]:
    """Return all keys that map one supplied plaintext to ciphertext."""
    result = brute_force_keys(((plaintext, ciphertext),))
    return result.candidate_keys


def analyze_plaintext_collisions(plaintext: str) -> CollisionAnalysis:
    """Check whether distinct keys encrypt a fixed block to equal ciphertexts."""
    if len(plaintext) != 8 or any(bit not in "01" for bit in plaintext):
        raise ValueError("plaintext must contain exactly 8 binary bits")

    by_ciphertext: dict[str, list[str]] = defaultdict(list)
    for key in _all_keys():
        by_ciphertext[encrypt_block(plaintext, key)].append(key)

    collisions = {
        ciphertext: tuple(keys)
        for ciphertext, keys in by_ciphertext.items()
        if len(keys) > 1
    }
    largest = max((len(keys) for keys in by_ciphertext.values()), default=0)
    return CollisionAnalysis(
        plaintext=plaintext,
        distinct_ciphertexts=len(by_ciphertext),
        ciphertexts_with_multiple_keys=len(collisions),
        maximum_keys_for_ciphertext=largest,
        collisions=collisions,
    )


def analyze_all_plaintexts() -> FullPlaintextAnalysis:
    """Exhaustively check key collisions for all 256 possible plaintexts."""
    collided = 0
    distinct_counts = []
    keys = tuple(_all_keys())
    for value in range(1 << 8):
        plaintext = format(value, "08b")
        ciphertexts = {encrypt_block(plaintext, key) for key in keys}
        distinct_counts.append(len(ciphertexts))
        if len(ciphertexts) < len(keys):
            collided += 1
    return FullPlaintextAnalysis(
        plaintext_blocks_checked=1 << 8,
        keys_checked_per_plaintext=len(keys),
        plaintexts_with_collisions=collided,
        minimum_distinct_ciphertexts=min(distinct_counts),
        maximum_distinct_ciphertexts=max(distinct_counts),
    )
