"""Hill cipher over a configurable alphabet.

The Hill cipher encrypts blocks of ``n`` characters at a time by multiplying an
``n x n`` key matrix with a block (column vector) of character indices:

    C = K * P  (mod m)

where ``m = len(alphabet)``.  Decryption uses the inverse matrix ``K^-1``:

    P = K^-1 * C  (mod m)

The catch is that ``K`` must be *invertible modulo m*.  For the modular inverse
to exist, ``det(K)`` must be coprime with ``m`` (``gcd(det(K), m) == 1``).  This
is the single most error-prone part of the Hill cipher:

* The determinant is computed **modulo m**, not over the integers.
* When ``m`` is prime (e.g. 26 is *not* prime -- 26 = 2 * 13), almost any
  non-zero determinant works; but with a composite modulus (26, or 95 = 5*19)
  a matrix whose determinant shares a factor with ``m`` has no inverse.
* The inverse is ``det^-1 * adj(K)`` (adjugate), where ``det^-1`` is the
  *modular* inverse of the determinant found via the extended Euclidean
  algorithm.

The adjugate/cofactor approach used here is exact and easy to read, but it is
``O(n!)``, so it is only practical for small matrices (2x2, 3x3, maybe 4x4) --
which is exactly the use case for this thesis.

This module operates on text whose length is a **multiple of the block size
``n``**.  Padding to a full block is handled by the caller (the ``hybrid``
pipeline), so that padding information is not lost when the transposition layer
permutes the characters afterwards.

.. note::

   Validating the key matrix (and inverting it) is an ``O(n!)`` operation.  To
   keep timing measurements honest, ``encrypt``/``decrypt`` accept a
   ``validate`` flag; pass ``validate=False`` when the matrix has already been
   validated (and, for decryption, when the precomputed ``inverse`` is supplied
   via :func:`prepare_key`).  See the ``algorithms`` module, which calls
   :func:`prepare_key` exactly once at setup.
"""

import random

from alphabet import (
    DEFAULT_ALPHABET,
    char_to_index,
    index_to_char,
    validate_alphabet,
)


# ---------------------------------------------------------------------------
# Modular arithmetic helpers
# ---------------------------------------------------------------------------
def extended_gcd(a, b):
    """Return ``(g, x, y)`` such that ``a*x + b*y == g == gcd(a, b)``."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    return g, y1, x1 - (a // b) * y1


def mod_inverse(a, m):
    """Return the modular inverse of *a* modulo *m*, or ``None`` if none exists.

    The inverse exists iff ``gcd(a, m) == 1``.
    """
    a %= m
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        return None
    return x % m


# ---------------------------------------------------------------------------
# Matrix helpers (all arithmetic done modulo m)
# ---------------------------------------------------------------------------
def determinant(matrix, m):
    """Determinant of a square *matrix* modulo *m* (cofactor expansion).

    Suitable for small matrices (n <= ~4).  Larger matrices should use Gaussian
    elimination over a prime field instead.
    """
    n = len(matrix)
    if n == 1:
        return matrix[0][0] % m
    if n == 2:
        return (matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]) % m

    det = 0
    for col in range(n):
        minor = [
            [row[c] for c in range(n) if c != col]
            for row in matrix[1:]
        ]
        term = matrix[0][col] * determinant(minor, m)
        det = (det + term if col % 2 == 0 else det - term) % m
    return det % m


def adjugate(matrix, m):
    """Adjugate (transposed cofactor matrix) of *matrix* modulo *m*."""
    n = len(matrix)
    if n == 1:
        return [[1]]

    adj = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            minor = [
                [row[c] for c in range(n) if c != j]
                for r, row in enumerate(matrix) if r != i
            ]
            cofactor = determinant(minor, m)
            if (i + j) % 2 == 1:
                cofactor = -cofactor
            adj[j][i] = cofactor % m  # note: transpose here
    return adj


def matrix_inverse(matrix, m):
    """Return the inverse of *matrix* modulo *m*.

    Raises ``ValueError`` with a clear message if the matrix is not invertible
    modulo *m* (i.e. ``gcd(det, m) != 1``).
    """
    n = len(matrix)
    det = determinant(matrix, m) % m
    det_inv = mod_inverse(det, m)
    if det_inv is None:
        raise ValueError(
            "Hill key matrix is NOT invertible modulo {}: determinant = {} "
            "shares a common factor with {} (gcd = {}). "
            "Choose a matrix whose determinant is coprime with the modulus."
            .format(m, det, m, _gcd(det, m))
        )
    adj = adjugate(matrix, m)
    return [
        [(adj[i][j] * det_inv) % m for j in range(n)]
        for i in range(n)
    ]


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


# ---------------------------------------------------------------------------
# Key matrix validation
# ---------------------------------------------------------------------------
def _normalize_matrix(matrix, alphabet):
    """Validate the *shape* of a key matrix and return it normalized.

    Checks that the matrix is a non-empty square matrix of integers in
    ``0..m-1``.  Does **not** compute the inverse (which is ``O(n!)``); use
    :func:`validate_key_matrix` or :func:`prepare_key` when invertibility must
    also be verified.

    Raises:
        ValueError: if the matrix is malformed.
    """
    m = len(validate_alphabet(alphabet))
    if not isinstance(matrix, (list, tuple)) or len(matrix) == 0:
        raise ValueError("key matrix must be a non-empty list of rows")

    n = len(matrix)
    normalized = []
    for i, row in enumerate(matrix):
        if not isinstance(row, (list, tuple)) or len(row) != n:
            raise ValueError(
                "key matrix must be square; row {} has length {}, expected {}"
                .format(i, len(row) if isinstance(row, (list, tuple)) else 0, n)
            )
        norm_row = []
        for j, value in enumerate(row):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(
                    "matrix entry [{},{}] = {!r} is not an integer"
                    .format(i, j, value)
                )
            if not 0 <= value < m:
                raise ValueError(
                    "matrix entry [{},{}] = {} is out of range [0, {})"
                    .format(i, j, value, m)
                )
            norm_row.append(value)
        normalized.append(norm_row)
    return normalized


def validate_key_matrix(matrix, alphabet=DEFAULT_ALPHABET):
    """Validate a Hill key matrix and return it normalized (all ints, mod m).

    Checks that the matrix is a non-empty square matrix of integers in
    ``0..m-1`` and that it is invertible modulo ``m``.

    Raises:
        ValueError: if the matrix is malformed or has no modular inverse.
    """
    normalized = _normalize_matrix(matrix, alphabet)
    m = len(validate_alphabet(alphabet))
    # This raises ValueError with a clear message when the inverse is missing.
    matrix_inverse(normalized, m)
    return normalized


def prepare_key(key_matrix, alphabet=DEFAULT_ALPHABET):
    """Validate *key_matrix* once and return ``(matrix, inverse)``.

    This performs the (expensive, ``O(n!)``) validation + inversion a *single*
    time.  Callers should do this once at setup and then pass ``validate=False``
    (and, for decryption, ``inverse=...``) to :func:`encrypt`/:func:`decrypt`,
    so the per-call cost reflects only the actual cipher arithmetic.

    Args:
        key_matrix (list[list[int]]): square ``n x n`` key matrix.
        alphabet (str): character set (modulus).

    Returns:
        tuple: ``(normalized_matrix, inverse_matrix)``.
    """
    normalized = _normalize_matrix(key_matrix, alphabet)
    m = len(validate_alphabet(alphabet))
    inverse = matrix_inverse(normalized, m)
    return normalized, inverse


def generate_key_matrix(n, alphabet=DEFAULT_ALPHABET, seed=None):
    """Generate a random, valid ``n x n`` Hill key matrix over *alphabet*.

    The matrix is guaranteed to be invertible modulo ``m = len(alphabet)``.
    Useful when a caller wants a key of a configurable size without having to
    find a valid matrix by hand.

    Args:
        n (int): matrix size (must be >= 1).
        alphabet (str): character set that determines the modulus.
        seed (int | None): optional seed for reproducibility.

    Returns:
        list[list[int]]: an ``n x n`` key matrix.
    """
    m = len(validate_alphabet(alphabet))
    if n < 1:
        raise ValueError("matrix size n must be >= 1")
    rng = random.Random(seed)
    while True:
        matrix = [[rng.randrange(m) for _ in range(n)] for _ in range(n)]
        if mod_inverse(determinant(matrix, m), m) is not None:
            return matrix


# ---------------------------------------------------------------------------
# Block encryption / decryption
# ---------------------------------------------------------------------------
def _text_to_indices(text, alphabet):
    m = len(alphabet)
    indices = []
    for ch in text:
        idx = char_to_index(ch, alphabet)
        if idx == -1:
            raise ValueError(
                "character {!r} is not in the alphabet (size {})".format(ch, m)
            )
        indices.append(idx)
    return indices


def _indices_to_text(indices, alphabet):
    return "".join(index_to_char(i, alphabet) for i in indices)


def _multiply_block(key_matrix, block, m):
    """Return ``key_matrix * block`` (mod m) for a single column vector."""
    return [
        sum(key_matrix[row][col] * block[col] for col in range(len(block))) % m
        for row in range(len(key_matrix))
    ]


def encrypt(plaintext, key_matrix, alphabet=DEFAULT_ALPHABET, validate=True):
    """Encrypt *plaintext* with the Hill cipher.

    Args:
        plaintext (str): text whose length must be a multiple of the block size
            (``len(key_matrix)``).  Use ``pad_to_multiple`` first if needed.
        key_matrix (list[list[int]]): square ``n x n`` key matrix.
        alphabet (str): character set (modulus).
        validate (bool): if ``True`` (default), re-validate and normalize the
            matrix on every call.  Set ``False`` when the matrix was already
            validated via :func:`prepare_key` (important for timing benchmarks).

    Returns:
        str: ciphertext (same length as *plaintext*).
    """
    validate_alphabet(alphabet)
    if validate:
        matrix = validate_key_matrix(key_matrix, alphabet)
    else:
        matrix = key_matrix
    n = len(matrix)
    m = len(alphabet)

    if len(plaintext) % n != 0:
        raise ValueError(
            "plaintext length {} is not a multiple of the block size {}; "
            "pad it first with pad_to_multiple()".format(len(plaintext), n)
        )

    indices = _text_to_indices(plaintext, alphabet)
    out = []
    for i in range(0, len(indices), n):
        block = indices[i:i + n]
        out.extend(_multiply_block(matrix, block, m))
    return _indices_to_text(out, alphabet)


def decrypt(ciphertext, key_matrix, alphabet=DEFAULT_ALPHABET, validate=True,
            inverse=None):
    """Decrypt *ciphertext* with the Hill cipher.

    Inverse of :func:`encrypt`; *ciphertext* length must be a multiple of the
    block size.

    Args:
        ciphertext (str): text to decrypt.
        key_matrix (list[list[int]]): square ``n x n`` key matrix.
        alphabet (str): character set (modulus).
        validate (bool): if ``True`` (default), re-validate the matrix on every
            call.  Set ``False`` for benchmarking.
        inverse (list[list[int]] | None): precomputed inverse matrix.  When
            ``None`` it is computed on demand (``O(n!)``).  Precompute it once
            with :func:`prepare_key` and pass it here for repeated calls.

    Returns:
        str: plaintext (same length as *ciphertext*).
    """
    validate_alphabet(alphabet)
    if validate:
        matrix = validate_key_matrix(key_matrix, alphabet)
    else:
        matrix = key_matrix
    n = len(matrix)
    m = len(alphabet)

    if len(ciphertext) % n != 0:
        raise ValueError(
            "ciphertext length {} is not a multiple of the block size {}"
            .format(len(ciphertext), n)
        )

    if inverse is None:
        inverse = matrix_inverse(matrix, m)
    indices = _text_to_indices(ciphertext, alphabet)
    out = []
    for i in range(0, len(indices), n):
        block = indices[i:i + n]
        out.extend(_multiply_block(inverse, block, m))
    return _indices_to_text(out, alphabet)


# ---------------------------------------------------------------------------
# Padding helpers (used by the hybrid pipeline)
# ---------------------------------------------------------------------------
def pad_length(length, block_size):
    """Number of padding characters needed to reach a multiple of *block_size*."""
    return (-length) % block_size


def pad_to_multiple(text, block_size, pad_char):
    """Right-pad *text* with *pad_char* to a multiple of *block_size*."""
    return text + pad_char * pad_length(len(text), block_size)
