"""Utilitas bersama untuk modul uji serangan (kriptanalisis).

Berisi:
* konversi teks <-> indeks A-Z,
* aljabar matriks 3x3 modulo 26 (versi cepat, tanpa validasi berulang),
* pembangkitan kunci acak untuk tiap percobaan,
* pembangun skenario dengan kunci kustom (memakai kode asli skripsi),
* konversi urutan kolom <-> kunci string transposisi.

Semua serangan memakai implementasi cipher ASLI dari skripsi
(``algorithms.py``, ``hill.py``, ``transposition.py``) untuk membuat
ciphertext, sehingga hasil serangan berlaku untuk implementasi yang diuji.
"""

import itertools
import os
import sys
import time

# Pastikan modul skripsi (algorithms, hill, ...) bisa diimpor dari folder induk.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import algorithms  # noqa: E402
import hill  # noqa: E402
import transposition  # noqa: E402
from alphabet import ALPHABET_26  # noqa: E402

M = 26
ALPHA = ALPHABET_26


# ---------------------------------------------------------------------------
# Konversi teks
# ---------------------------------------------------------------------------
def to_idx(text):
    return [ord(c) - 65 for c in text]


def to_str(indices):
    return "".join(chr(65 + (x % M)) for x in indices)


# ---------------------------------------------------------------------------
# Aljabar 3x3 mod 26 (cepat)
# ---------------------------------------------------------------------------
def det3(a):
    return (a[0][0] * (a[1][1] * a[2][2] - a[1][2] * a[2][1])
            - a[0][1] * (a[1][0] * a[2][2] - a[1][2] * a[2][0])
            + a[0][2] * (a[1][0] * a[2][1] - a[1][1] * a[2][0])) % M


def inv3(a):
    """Invers matriks 3x3 modulo 26, atau ``None`` bila tidak invertibel."""
    d = det3(a)
    d_inv = hill.mod_inverse(d, M)
    if d_inv is None:
        return None
    adj = hill.adjugate(a, M)
    return [[(adj[i][j] * d_inv) % M for j in range(3)] for i in range(3)]


def matmul3(x, y):
    return [[sum(x[i][k] * y[k][j] for k in range(3)) % M for j in range(3)]
            for i in range(3)]


def matvec3(x, v):
    return [(x[0][0] * v[0] + x[0][1] * v[1] + x[0][2] * v[2]) % M,
            (x[1][0] * v[0] + x[1][1] * v[1] + x[1][2] * v[2]) % M,
            (x[2][0] * v[0] + x[2][1] * v[1] + x[2][2] * v[2]) % M]


def blocks(indices, n=3):
    return [indices[i:i + n] for i in range(0, len(indices) - n + 1, n)]


# ---------------------------------------------------------------------------
# Transposisi: urutan kolom <-> kunci string
# ---------------------------------------------------------------------------
def order_to_key(order):
    """Ubah urutan baca kolom (mis. (2,0,1)) menjadi kunci string ('BCA').

    Dijamin ``transposition._column_order(order_to_key(o)) == list(o)``.
    """
    key = [None] * len(order)
    for rank, col in enumerate(order):
        key[col] = chr(65 + rank)
    return "".join(key)


def all_orders(n_cols):
    return itertools.permutations(range(n_cols))


def undo_transposition(text, order):
    return transposition.decrypt(text, order_to_key(order))


# ---------------------------------------------------------------------------
# Kunci acak & pembangun skenario
# ---------------------------------------------------------------------------
def random_keys(rng, vig_len=5, hill_n=3, trans_cols=6):
    """Bangkitkan satu set kunci acak (Vigenere, Hill, Transposisi)."""
    vig = "".join(rng.choice(ALPHA) for _ in range(vig_len))
    hill_matrix = hill.generate_key_matrix(hill_n, ALPHA,
                                           seed=rng.randrange(2 ** 31))
    order = list(range(trans_cols))
    rng.shuffle(order)
    return {"vigenere": vig, "hill": hill_matrix,
            "transposition": order_to_key(order),
            "transposition_order": tuple(order)}


def build_scenario(components, keys):
    """Bangun objek Scenario (kode asli skripsi) dengan kunci *keys*."""
    kw = {}
    if "Vigenere" in components:
        kw["vigenere_key"] = keys["vigenere"]
    if "Hill" in components:
        mat, inv = hill.prepare_key(keys["hill"], ALPHA)
        kw["hill_matrix"] = mat
        kw["hill_inverse"] = inv
    if "Transposisi" in components:
        kw["transposition_key"] = keys["transposition"]
    name = " + ".join(components)
    return algorithms._build_scenario(name, list(components), **kw)


def pad_like_scheme(plaintext):
    """Padding Hill persis seperti skema skripsi (Kerckhoffs: skema publik)."""
    return plaintext + "A" * ((-len(plaintext)) % 3)


class Timer:
    def __enter__(self):
        self.t0 = time.perf_counter()
        return self

    def __exit__(self, *exc):
        self.seconds = time.perf_counter() - self.t0
        return False
