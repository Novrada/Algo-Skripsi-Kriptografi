"""Vigenère cipher over a configurable alphabet.

The Vigenère cipher encrypts each character of the plaintext by adding the
corresponding character of a repeating keyword, modulo ``m = len(alphabet)``.

    C_i = (P_i + K_(i mod k)) mod m

Decryption simply subtracts the key character instead of adding it.

Behavior for characters *outside* the alphabet: they are preserved unchanged
and do **not** advance the key.  This is a standard convention (mirroring how
the classic A-Z Vigenère treats spaces/punctuation).  In the hybrid pipeline we
use ``ALPHABET_95`` by default, so there are normally no out-of-alphabet
characters at all.
"""

from alphabet import (
    DEFAULT_ALPHABET,
    char_to_index,
    index_to_char,
    validate_alphabet,
)


def _key_indices(key, alphabet):
    """Convert *key* into a list of indices, validating each character."""
    if not isinstance(key, str) or len(key) == 0:
        raise ValueError("key must be a non-empty string")
    indices = []
    for ch in key:
        idx = char_to_index(ch, alphabet)
        if idx == -1:
            raise ValueError(
                "key character {!r} is not in the alphabet".format(ch)
            )
        indices.append(idx)
    return indices


def _transform(text, key, alphabet, sign):
    """Core Vigenère transformation.

    ``sign`` is ``+1`` for encryption and ``-1`` for decryption.
    """
    validate_alphabet(alphabet)
    key_indices = _key_indices(key, alphabet)
    m = len(alphabet)
    key_len = len(key_indices)

    result = []
    key_pos = 0  # advances only on in-alphabet characters
    for ch in text:
        idx = char_to_index(ch, alphabet)
        if idx == -1:
            result.append(ch)  # preserve out-of-alphabet characters
            continue
        shift = key_indices[key_pos % key_len]
        new_idx = (idx + sign * shift) % m
        result.append(index_to_char(new_idx, alphabet))
        key_pos += 1
    return "".join(result)


def encrypt(plaintext, key, alphabet=DEFAULT_ALPHABET):
    """Encrypt *plaintext* with Vigenère using *key*.

    Args:
        plaintext (str): The message to encrypt.
        key (str): Non-empty keyword. All of its characters must be in
            *alphabet*.
        alphabet (str): Ordered character set (default: printable ASCII).

    Returns:
        str: The ciphertext (same length as the plaintext).
    """
    return _transform(plaintext, key, alphabet, sign=+1)


def decrypt(ciphertext, key, alphabet=DEFAULT_ALPHABET):
    """Decrypt *ciphertext* with Vigenère using *key*.

    Inverse of :func:`encrypt`: ``decrypt(encrypt(x, k), k) == x``.
    """
    return _transform(ciphertext, key, alphabet, sign=-1)
