"""S-DES implementation for the Information Security assignment.

Bit positions in permutation tables are numbered from left to right, starting
at 1. The S-box values follow the assignment document (including its SBox2).
"""

from __future__ import annotations

P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
LS1 = (2, 3, 4, 5, 1)
LS2 = (3, 4, 5, 1, 2)
IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)
EP = (4, 1, 2, 3, 2, 3, 4, 1)
P4 = (2, 4, 3, 1)

SBOX1 = (
    (1, 0, 3, 2),
    (3, 2, 1, 0),
    (0, 2, 1, 3),
    (3, 1, 0, 2),
)
SBOX2 = (
    (0, 1, 2, 3),
    (2, 3, 1, 0),
    (3, 0, 1, 2),
    (2, 1, 0, 3),
)


def _validate_bits(bits: str, expected_length: int, label: str) -> None:
    if not isinstance(bits, str):
        raise TypeError(f"{label} must be a string of 0s and 1s")
    if len(bits) != expected_length or any(bit not in "01" for bit in bits):
        raise ValueError(f"{label} must contain exactly {expected_length} bits")


def _permute(bits: str, positions: tuple[int, ...]) -> str:
    """Select bits using 1-based positions counted from the left."""
    return "".join(bits[position - 1] for position in positions)


def _xor(left: str, right: str) -> str:
    return "".join("1" if a != b else "0" for a, b in zip(left, right))


def _sbox_lookup(bits: str, box: tuple[tuple[int, ...], ...]) -> str:
    # S-DES uses the outer bits as the row and the inner bits as the column.
    row = int(bits[0] + bits[3], 2)
    column = int(bits[1:3], 2)
    return format(box[row][column], "02b")


def generate_subkeys(key: str) -> tuple[str, str]:
    """Return the two 8-bit round keys for a 10-bit binary key."""
    _validate_bits(key, 10, "key")
    permuted = _permute(key, P10)
    left, right = permuted[:5], permuted[5:]

    left1, right1 = _permute(left, LS1), _permute(right, LS1)
    key1 = _permute(left1 + right1, P8)

    left2, right2 = _permute(left1, LS2), _permute(right1, LS2)
    key2 = _permute(left2 + right2, P8)
    return key1, key2


def _fk(bits: str, subkey: str) -> str:
    left, right = bits[:4], bits[4:]
    mixed = _xor(_permute(right, EP), subkey)
    left_sub = _sbox_lookup(mixed[:4], SBOX1)
    right_sub = _sbox_lookup(mixed[4:], SBOX2)
    substituted = _permute(left_sub + right_sub, P4)
    return _xor(left, substituted) + right


def _switch(bits: str) -> str:
    return bits[4:] + bits[:4]


def encrypt_block(plaintext: str, key: str) -> str:
    """Encrypt one 8-bit binary plaintext block using a 10-bit key."""
    _validate_bits(plaintext, 8, "plaintext")
    key1, key2 = generate_subkeys(key)
    state = _permute(plaintext, IP)
    state = _fk(state, key1)
    state = _fk(_switch(state), key2)
    return _permute(state, IP_INV)


def decrypt_block(ciphertext: str, key: str) -> str:
    """Decrypt one 8-bit binary ciphertext block using a 10-bit key."""
    _validate_bits(ciphertext, 8, "ciphertext")
    key1, key2 = generate_subkeys(key)
    state = _permute(ciphertext, IP)
    state = _fk(state, key2)
    state = _fk(_switch(state), key1)
    return _permute(state, IP_INV)


def encrypt_bytes(data: bytes, key: str) -> bytes:
    """Encrypt bytes independently, one byte per S-DES block."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    _validate_bits(key, 10, "key")
    return bytes(int(encrypt_block(format(value, "08b"), key), 2) for value in data)


def decrypt_bytes(data: bytes, key: str) -> bytes:
    """Decrypt bytes independently, one byte per S-DES block."""
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    _validate_bits(key, 10, "key")
    return bytes(int(decrypt_block(format(value, "08b"), key), 2) for value in data)


def encrypt_text(text: str, key: str) -> str:
    """Encrypt ASCII text and return the ciphertext as hexadecimal text."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")
    try:
        data = text.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("text must contain ASCII characters only") from error
    return encrypt_bytes(data, key).hex().upper()


def decrypt_text(ciphertext_hex: str, key: str) -> str:
    """Decrypt hexadecimal ciphertext and decode the result as ASCII text."""
    if not isinstance(ciphertext_hex, str):
        raise TypeError("ciphertext_hex must be a string")
    try:
        data = bytes.fromhex(ciphertext_hex)
    except ValueError as error:
        raise ValueError("ciphertext must be an even-length hexadecimal string") from error
    try:
        return decrypt_bytes(data, key).decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("decrypted bytes are not valid ASCII text") from error


if __name__ == "__main__":
    sample_plaintext = "10101010"
    sample_key = "1010000010"
    sample_ciphertext = encrypt_block(sample_plaintext, sample_key)
    print(f"Key:        {sample_key}")
    print(f"Subkeys:    {generate_subkeys(sample_key)}")
    print(f"Plaintext:  {sample_plaintext}")
    print(f"Ciphertext: {sample_ciphertext}")
    print(f"Decrypted:  {decrypt_block(sample_ciphertext, sample_key)}")
