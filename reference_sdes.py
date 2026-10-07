"""Implementation B: independent integer-bit S-DES, assignment parameter set.

Only Python's standard library is used. No imports from implementation A.
Positions count from the most significant bit, starting at 1.
"""

import argparse

P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INVERSE = (4, 1, 3, 5, 7, 2, 8, 6)
EXPANSION = (4, 1, 2, 3, 2, 3, 4, 1)
P4 = (2, 4, 3, 1)
S0 = (1, 0, 3, 2, 3, 2, 1, 0, 0, 2, 1, 3, 3, 1, 0, 2)
# Assignment's modified second S-box; final row is 2, 1, 0, 3.
S1 = (0, 1, 2, 3, 2, 3, 1, 0, 3, 0, 1, 2, 2, 1, 0, 3)


def _bit_value(bits: str, width: int) -> int:
    if not isinstance(bits, str):
        raise TypeError("binary inputs must be strings")
    if len(bits) != width or any(bit not in "01" for bit in bits):
        raise ValueError(f"expected exactly {width} binary bits")
    return int(bits, 2)


def _select(value: int, width: int, positions: tuple[int, ...]) -> int:
    selected = 0
    for position in positions:
        selected = (selected << 1) | ((value >> (width - position)) & 1)
    return selected


def _round_keys(key: int) -> tuple[int, int]:
    selected = _select(key, 10, P10)
    halves = [selected >> 5, selected & 31]
    keys = []
    for shift in (1, 2):
        halves = [((half << shift) | (half >> (5 - shift))) & 31 for half in halves]
        keys.append(_select((halves[0] << 5) | halves[1], 10, P8))
    return tuple(keys)


def generate_subkeys(key: str) -> tuple[str, str]:
    return tuple(format(value, "08b") for value in _round_keys(_bit_value(key, 10)))


def _round_function(right: int, subkey: int) -> int:
    expanded = _select(right, 4, EXPANSION) ^ subkey
    substituted = 0
    for nibble, table in ((expanded >> 4, S0), (expanded & 15, S1)):
        row = ((nibble >> 2) & 2) | (nibble & 1)
        column = (nibble >> 1) & 3
        substituted = (substituted << 2) | table[row * 4 + column]
    return _select(substituted, 4, P4)


def _transform(block: str, key: str, reverse_keys: bool) -> str:
    value = _bit_value(block, 8)
    round_keys = _round_keys(_bit_value(key, 10))
    if reverse_keys:
        round_keys = round_keys[::-1]
    initial = _select(value, 8, IP)
    left, right = initial >> 4, initial & 15
    for subkey in round_keys:
        left, right = right, left ^ _round_function(right, subkey)
    return format(_select((right << 4) | left, 8, IP_INVERSE), "08b")


def encrypt_block(plaintext: str, key: str) -> str:
    return _transform(plaintext, key, False)


def decrypt_block(ciphertext: str, key: str) -> str:
    return _transform(ciphertext, key, True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Independent S-DES implementation B")
    parser.add_argument("operation", choices=("encrypt", "decrypt"))
    parser.add_argument("block", help="8 binary bits")
    parser.add_argument("key", help="10 binary bits")
    arguments = parser.parse_args()
    operation = encrypt_block if arguments.operation == "encrypt" else decrypt_block
    try:
        print(operation(arguments.block, arguments.key))
    except (TypeError, ValueError) as error:
        parser.error(str(error))
