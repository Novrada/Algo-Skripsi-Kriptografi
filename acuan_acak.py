"""Acuan acak untuk cipher klasik (alfabet A-Z).

Entropi Shannon dan IC sampel berhingga selalu sedikit menyimpang dari nilai
teoretis (log2 26 dan 1/26).  Skrip ini menghitung rata-rata dan simpangan baku
IC dan entropi dari 100 teks acak A-Z (seragam) pada tiap ukuran sampel, sebagai
pembanding yang adil bagi ciphertext.  Keluaran: hasil/acuan_acak_klasik.csv

    python acuan_acak.py
"""
import csv
import os
import random
import statistics

import evaluation as ev

SEED = 2026
SIZES = [50, 100, 500, 1000, 5000]
REPEATS = 100
LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def main():
    rng = random.Random(SEED)
    os.makedirs("hasil", exist_ok=True)
    rows = []
    for size in SIZES:
        ics, hs = [], []
        for _ in range(REPEATS):
            text = "".join(rng.choice(LETTERS) for _ in range(size))
            ics.append(ev.index_of_coincidence(text))
            hs.append(ev.shannon_entropy(text))
        rows.append({
            "ukuran": size, "ulangan": REPEATS,
            "IC_rata2": round(statistics.mean(ics), 5),
            "IC_stdev": round(statistics.stdev(ics), 5),
            "entropi_rata2": round(statistics.mean(hs), 5),
            "entropi_stdev": round(statistics.stdev(hs), 5),
        })
        print(rows[-1])
    with open(os.path.join("hasil", "acuan_acak_klasik.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    main()
