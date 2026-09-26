"""Model bahasa Indonesia sederhana untuk penilaian (scoring) hasil serangan.

PENTING (validitas eksperimen): statistik bahasa yang dipakai penyerang harus
berasal dari korpus REFERENSI yang TERPISAH dari plaintext yang diserang.

* Bila file ``serangan/korpus_referensi.txt`` ada (disarankan: kumpulan
  artikel Wikipedia bahasa Indonesia, >= 50.000 huruf), file itu dipakai.
* Bila tidak ada, dipakai fallback: dokumen UU ITE + UU PDP dari
  ``sample_data`` sebagai referensi, dan plaintext serangan diambil HANYA dari
  dokumen lain (Pancasila, Proklamasi, UUD 1945).  Fallback ini sah (tidak
  tumpang-tindih) tetapi korpusnya kecil; laporkan mana yang dipakai.
"""

import math
import os

import sample_data

_HERE = os.path.dirname(os.path.abspath(__file__))
REFERENCE_FILE = os.path.join(_HERE, "korpus_referensi.txt")

_FALLBACK_REFERENCE_DOCS = ("Pasal UU ITE", "Pasal UU PDP")


def _docs(names):
    return "".join(sample_data.normalize_az(t)
                   for n, t in sample_data.DOKUMEN if n in names)


def reference_text():
    """Kembalikan (teks_referensi_AZ, keterangan_sumber)."""
    if os.path.exists(REFERENCE_FILE):
        with open(REFERENCE_FILE, encoding="utf-8") as f:
            return (sample_data.normalize_az(f.read()),
                    "file korpus_referensi.txt")
    return (_docs(_FALLBACK_REFERENCE_DOCS),
            "fallback: UU ITE + UU PDP (sample_data)")


def attack_plaintext_pool():
    """Kumpulan plaintext untuk diserang (tidak tumpang-tindih referensi)."""
    if os.path.exists(REFERENCE_FILE):
        return sample_data.corpus_normal()
    others = [n for n, _ in sample_data.DOKUMEN
              if n not in _FALLBACK_REFERENCE_DOCS]
    return _docs(others)


class LanguageModel:
    """Frekuensi unigram + model n-gram (log10) dari korpus referensi."""

    def __init__(self, text, n=3):
        self.n = n
        counts = [0] * 26
        for ch in text:
            counts[ord(ch) - 65] += 1
        total = sum(counts)
        # frekuensi unigram (dengan smoothing kecil agar tidak nol)
        self.unigram = [(c + 0.5) / (total + 13.0) for c in counts]

        grams = {}
        for i in range(len(text) - n + 1):
            g = text[i:i + n]
            grams[g] = grams.get(g, 0) + 1
        gtotal = sum(grams.values())
        self.logp = {g: math.log10(c / gtotal) for g, c in grams.items()}
        self.floor = math.log10(0.01 / gtotal)

    def score(self, text):
        """Skor log-likelihood per n-gram (lebih besar = lebih mirip bahasa)."""
        n = self.n
        k = len(text) - n + 1
        if k <= 0:
            return self.floor
        lp, fl = self.logp, self.floor
        return sum(lp.get(text[i:i + n], fl) for i in range(k)) / k

    def chi_squared(self, counts):
        """Chi-squared antara hitungan huruf dan frekuensi referensi."""
        total = sum(counts)
        if total == 0:
            return 0.0
        return sum((c - total * p) ** 2 / (total * p)
                   for c, p in zip(counts, self.unigram))
