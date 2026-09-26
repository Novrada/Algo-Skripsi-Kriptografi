"""Metrik level byte/bit untuk AES, beserta versi ternormalisasi.

Metrik yang disediakan:

* avalanche bit (persen bit berbeda dari 128 bit ciphertext),
* entropi Shannon level byte (maksimum teoretis 8 bit),
* Index of Coincidence level byte (nilai acak ideal 1/256).

Normalisasi (bagian 5 dokumen spesifikasi):

* entropi ternormalisasi  = H / 8,
* rasio IC                = IC x 256,
* avalanche ternormalisasi = avalanche_bit / 50%.

Semua nilai normalisasi dirancang agar nilainya mendekati 1,0 untuk data yang
benar-benar acak, sehingga bisa disandingkan dengan cipher klasik (yang
dinormalkan terhadap log2(26), 1/26, dan 96,15%).
"""

import math


def shannon_entropy_bytes(data):
    """Entropi Shannon (bit) dari *data* (bytes), atas 256 simbol."""
    n = len(data)
    if n == 0:
        return 0.0
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    entropy = 0.0
    for c in counts.values():
        p = c / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def index_of_coincidence_bytes(data):
    """Index of Coincidence atas 256 simbol byte.

    IC = sum(n_i * (n_i - 1)) / (N * (N - 1)).  Data acak mendekati 1/256.
    """
    n = len(data)
    if n < 2:
        return 0.0
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    total = sum(c * (c - 1) for c in counts.values())
    return total / (n * (n - 1))


def normalized_entropy_byte(entropy_bits):
    """Entropi byte ternormalisasi: H / 8."""
    return entropy_bits / 8.0


def ic_ratio_bytes(ic):
    """Rasio IC byte: IC x 256 (1,0 untuk data acak)."""
    return ic * 256.0


def normalized_avalanche_bit(percent):
    """Avalanche bit ternormalisasi: persen / 50%."""
    return percent / 50.0
