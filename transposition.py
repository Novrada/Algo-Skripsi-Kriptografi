"""Columnar Transposition cipher.

The columnar transposition cipher writes the plaintext row by row into a grid
whose width is the number of letters in the keyword, then reads it column by
column in the order defined by the (sorted) keyword.  Decryption reverses the
process.

Key implementation detail -- handling lengths that are not a multiple of the
number of columns:

The classic textbook version pads the text so its length is an exact multiple
of the column count.  Here we deliberately use a *ragged* (unpadded) grid
instead: the last row is simply shorter.  This makes the cipher length-
preserving, which is important in the hybrid pipeline, because the Hill layer
(which runs *before* this one) is the only layer that changes the text length.
If transposition also padded, the padding characters would be scattered by the
permutation and become hard to remove reliably.

To decrypt a ragged grid we only need to know how many columns are "long" (have
one extra cell): exactly ``len(ciphertext) % cols`` columns are long (or all of
them when the length is an exact multiple).
"""


def _column_order(key):
    """Return the column indices sorted by keyword character.

    Sorting is made stable by breaking ties with the original index, so a key
    with repeated letters still produces a deterministic, reversible order.
    """
    return [i for i, _ in sorted(enumerate(key), key=lambda t: (t[1], t[0]))]


def encrypt(plaintext, key):
    """Encrypt *plaintext* with columnar transposition using *key*.

    Args:
        plaintext (str): text to encrypt (any characters, any length).
        key (str): non-empty keyword; each character defines one column.

    Returns:
        str: ciphertext of the same length as *plaintext*.
    """
    if not isinstance(key, str) or len(key) == 0:
        raise ValueError("key must be a non-empty string")

    cols = len(key)
    length = len(plaintext)
    if length == 0:
        return ""

    order = _column_order(key)
    rows = (length + cols - 1) // cols

    result = []
    for col in order:
        for row in range(rows):
            idx = row * cols + col
            if idx < length:
                result.append(plaintext[idx])
    return "".join(result)


def decrypt(ciphertext, key):
    """Decrypt *ciphertext* with columnar transposition using *key*.

    Inverse of :func:`encrypt`: ``decrypt(encrypt(x, k), k) == x``.
    """
    if not isinstance(key, str) or len(key) == 0:
        raise ValueError("key must be a non-empty string")

    cols = len(key)
    length = len(ciphertext)
    if length == 0:
        return ""

    order = _column_order(key)
    rows = (length + cols - 1) // cols

    # The first ``long_cols`` columns have ``rows`` cells; the rest have
    # ``rows - 1`` cells.
    long_cols = length % cols
    if long_cols == 0:
        long_cols = cols

    # Re-fill each column (in keyword order) with its slice of the ciphertext.
    col_texts = [None] * cols
    pos = 0
    for col in order:
        height = rows if col < long_cols else rows - 1
        col_texts[col] = ciphertext[pos:pos + height]
        pos += height

    # Read the grid back row by row.
    result = []
    for row in range(rows):
        for col in range(cols):
            if row < len(col_texts[col]):
                result.append(col_texts[col][row])
    return "".join(result)
