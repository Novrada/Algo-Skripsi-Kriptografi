"""Shared alphabet definitions and helpers for the hybrid cipher.

The whole pipeline (Vigenère -> Hill -> Columnar Transposition) works over a
single, configurable *alphabet*: an ordered list of unique characters.  Each
character is mapped to an integer index ``0..m-1`` and every arithmetic
operation in the ciphers is performed modulo ``m = len(alphabet)``.

Two alphabets are provided:

* ``ALPHABET_26`` -- the 26 uppercase English letters (classic textbook mode).
* ``ALPHABET_95`` -- all 95 printable ASCII characters (ASCII 32..126),
  including the space, digits, and punctuation.  This is the default because it
  lets us encrypt arbitrary text without having to strip or preserve
  non-alphabetic characters.

Choosing the alphabet is a deliberate design decision:

* With ``ALPHABET_26`` any character outside ``A-Z`` (spaces, digits, ...)
  cannot be represented and must either be removed beforehand or preserved
  separately (only Vigenère supports that).
* With ``ALPHABET_95`` *every* printable character participates in the
  encryption, so there is effectively nothing to ignore or preserve.

Note that ``95 = 5 * 19`` is composite (not prime).  This matters for the Hill
cipher: a key matrix is invertible iff its determinant is coprime with the
modulus, so we must validate ``gcd(det, m) == 1`` (see ``hill.py``).
"""

ALPHABET_26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# All printable ASCII characters: space (32) through tilde (126), 95 in total.
ALPHABET_95 = "".join(chr(c) for c in range(32, 127))

#: Default alphabet used by every cipher unless overridden.
DEFAULT_ALPHABET = ALPHABET_95


def validate_alphabet(alphabet):
    """Validate and return *alphabet*.

    Raises ``ValueError`` if the alphabet is not a non-empty string of unique
    characters.
    """
    if not isinstance(alphabet, str):
        raise TypeError("alphabet must be a string")
    if len(alphabet) == 0:
        raise ValueError("alphabet must not be empty")
    if len(set(alphabet)) != len(alphabet):
        raise ValueError("alphabet must contain only unique characters")
    return alphabet


def char_to_index(ch, alphabet=DEFAULT_ALPHABET):
    """Return the index of *ch* in *alphabet*, or ``-1`` if it is absent."""
    return alphabet.find(ch)


def index_to_char(index, alphabet=DEFAULT_ALPHABET):
    """Return the character at *index* in *alphabet*."""
    return alphabet[index]


def validate_text(text, alphabet=DEFAULT_ALPHABET):
    """Raise ``ValueError`` if *text* contains a character outside *alphabet*.

    This is used by the hybrid pipeline to fail loudly instead of silently
    corrupting data when a character cannot be encoded.
    """
    m = len(alphabet)
    for i, ch in enumerate(text):
        if char_to_index(ch, alphabet) == -1:
            raise ValueError(
                "character {!r} at position {} is not in the alphabet "
                "(size {}). Use ALPHABET_95 for arbitrary printable text."
                .format(ch, i, m)
            )
    return text
