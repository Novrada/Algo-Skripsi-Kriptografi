"""Bangun tabel perbandingan ternormalisasi pada sampel 5000 huruf.

Bab III memakai sampel statistik 5000 huruf, sedangkan
``hasil/aes/tabel_perbandingan_ternormalisasi.csv`` (keluaran
``baseline_aes/run_aes.py``) memakai kolom IC/entropi dari tabel ringkasan
``hasil_perbandingan.csv`` yang berbasis 1000 huruf.

Skrip ini TIDAK mengukur ulang apa pun; semuanya dihitung dari CSV yang sudah
ada, sehingga waktu AES maupun waktu klasik tidak berubah:

* entropi/ideal dan rasio IC klasik : ``hasil/frekuensi_karakter.csv``
  (frekuensi A-Z pada sampel 5000 huruf), dibagi log2(26) dan 1/26.
* avalanche/ideal klasik            : ``hasil/avalanche.csv`` / 96,15.
* waktu enkripsi 1000 huruf klasik  : ``hasil_lama/hasil_perbandingan.csv``
  (data waktu laptop yang dipakai paper).
* baris AES-128/AES-256            : ``hasil/aes/aes_statistik.csv``,
  ``hasil/aes/aes_avalanche_bit.csv``, ``hasil/aes/aes_waktu_ringkasan.csv``.

Keluaran: hasil/tabel_perbandingan_ternormalisasi_5000.csv

    python buat_tabel_ternormalisasi.py
"""
import csv
import math
import os
import statistics

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOG2_26 = math.log2(26)
IC_RANDOM = 1.0 / 26
AVALANCHE_IDEAL_CLASSIC = 96.15     # 100 * 25/26, sesuai evaluation.AVALANCHE_IDEAL
AES_AVALANCHE_IDEAL = 50.0          # ideal avalanche bit
AES_ENTROPY_IDEAL = 8.0             # entropi byte ideal
REFERENCE_TIME_SIZE = "1000"
KEY_SPACE_BITS = {"AES-128": 128, "AES-256": 256}

HASIL = "hasil"
HASIL_LAMA = "hasil_lama"
OUT = os.path.join(HASIL, "tabel_perbandingan_ternormalisasi_5000.csv")

FIELDS = ["Skenario", "Entropi/ideal (5000)", "Rasio IC (5000)",
          "Avalanche/ideal", "Waktu enkripsi 1000 (ms, laptop)"]


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def entropy_and_ic(freq_row):
    counts = [int(freq_row[ch]) for ch in ALPHABET]
    n = sum(counts)
    entropy = -sum((c / n) * math.log2(c / n) for c in counts if c)
    ic = sum(c * (c - 1) for c in counts) / (n * (n - 1))
    return entropy, ic, n


def time_source():
    """Waktu enkripsi klasik diambil dari hasil_lama (data waktu paper)."""
    path = os.path.join(HASIL_LAMA, "hasil_perbandingan.csv")
    if not os.path.exists(path):
        path = os.path.join(HASIL, "hasil_perbandingan.csv")
    return path, read_csv(path)


def main():
    freq_rows = read_csv(os.path.join(HASIL, "frekuensi_karakter.csv"))
    aval_rows = {r["Skenario"]: r
                 for r in read_csv(os.path.join(HASIL, "avalanche.csv"))}
    time_path, time_rows = time_source()
    enc_by_name = {r["Skenario"]: float(r["Waktu Enkripsi (ms)"])
                   for r in time_rows}

    out = []
    for r in freq_rows:
        name = r["Skenario"]
        entropy, ic, n = entropy_and_ic(r)
        aval = float(aval_rows[name]["Avalanche Plaintext (%)"])
        out.append({
            "Skenario": name,
            "Entropi/ideal (5000)": round(entropy / LOG2_26, 3),
            "Rasio IC (5000)": round(ic / IC_RANDOM, 3),
            "Avalanche/ideal": round(aval / AVALANCHE_IDEAL_CLASSIC, 4),
            "Waktu enkripsi 1000 (ms, laptop)": enc_by_name[name],
        })
        print("{:<34} N={} H/ideal={:.3f} IC/acak={:.3f}".format(
            name, n, entropy / LOG2_26, ic / IC_RANDOM))

    # ---- baris AES (dari hasil/aes/, tanpa mengukur ulang) ----
    aes_dir = os.path.join(HASIL, "aes")
    stat_by = {r["varian"]: r
               for r in read_csv(os.path.join(aes_dir, "aes_statistik.csv"))}
    bit_rows = read_csv(os.path.join(aes_dir, "aes_avalanche_bit.csv"))
    time_aes = read_csv(os.path.join(aes_dir, "aes_waktu_ringkasan.csv"))
    enc_aes = {r["varian"]: float(r["mean_ms"]) for r in time_aes
               if r["ukuran"] == REFERENCE_TIME_SIZE and r["operasi"] == "enc"}

    for variant in ("AES-128", "AES-256"):
        s = stat_by[variant]
        vals = [float(r["persen"]) for r in bit_rows
                if r["varian"] == variant and r["jenis"] == "plaintext"]
        out.append({
            "Skenario": variant,
            "Entropi/ideal (5000)": round(
                float(s["entropi_byte"]) / AES_ENTROPY_IDEAL, 3),
            "Rasio IC (5000)": round(float(s["rasio_IC"]), 3),
            "Avalanche/ideal": round(
                statistics.mean(vals) / AES_AVALANCHE_IDEAL, 6),
            "Waktu enkripsi 1000 (ms, laptop)": enc_aes[variant],
        })

    with open(OUT, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        w.writerows(out)

    print("\nSumber waktu klasik : {}".format(time_path))
    print("Sumber statistik    : hasil/frekuensi_karakter.csv (5000 huruf)")
    print("Ditulis ke          : {}".format(OUT))


if __name__ == "__main__":
    main()
