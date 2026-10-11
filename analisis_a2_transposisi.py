"""Analisis kegagalan serangan A2 (transposisi, 3B): success=False tapi readable=True.

Skrip ini HANYA membaca hasil yang sudah ada (hasil/serangan/serangan_3B.csv) dan
merekonstruksi plaintext/ciphertext tiap percobaan dengan seed yang sama seperti
run_attacks.py, lalu memeriksa dugaan berikut:

  D1  Huruf yang berbeda menumpuk di ujung teks (baris terakhir grid yang tidak penuh).
  D2  Urutan kolom hasil adalah rotasi urutan asli.
  D3  Urutan kolom hasil adalah penukaran dua kolom bersebelahan.
  D4  Dua urutan itu menghasilkan plaintext identik kecuali pada baris terakhir
      yang tidak penuh.
  D5  Kegagalan berhubungan dengan panjang teks mod 6.

Dua pemeriksaan tambahan yang muncul dari data (bukan dugaan awal):

  D6  Urutan kolom hasil = urutan asli dengan setiap NILAI indeks digeser
      siklik sebesar k (mod jumlah kolom).
  D7  Plaintext hasil = plaintext asli yang tergeser d posisi secara utuh
      (sehingga kemiripan difflib tinggi walau tidak identik posisi-per-posisi).

Keluaran: hasil/analisis_tambahan/analisis_a2_transposisi.csv
          hasil/analisis_tambahan/analisis_a2_transposisi.txt

    python analisis_a2_transposisi.py
"""
import csv
import os
import random
import statistics

import transposition
from serangan.common import build_scenario, random_keys
from serangan.lang_model import attack_plaintext_pool

SEED = 2026
VIG_LEN = 5
HILL_N = 3
TRANS_COLS = 6
HELDOUT_LEN = 301
IN_CSV = os.path.join("hasil", "serangan", "serangan_3B.csv")
OUT_DIR = os.path.join("hasil", "analisis_tambahan")
LENGTHS = (100, 200, 500, 1000)


def _sample(pool, rng, length):
    start = rng.randrange(0, len(pool) - length)
    return pool[start:start + length]


def rebuild_trial(length, trial, pool):
    """Rekonstruksi plaintext dan ciphertext persis seperti run_attacks.run_trial."""
    rng = random.Random(SEED * 100003 + trial * 101 + length)
    keys = random_keys(rng, VIG_LEN, HILL_N, TRANS_COLS)
    scenario = build_scenario(["Transposisi"], keys)
    pt = _sample(pool, rng, length)
    _heldout = _sample(pool, rng, HELDOUT_LEN)
    body = scenario.cipher_body(pt)
    return pt, body, keys


def order_from_digits(s):
    return [int(c) for c in s]


def is_rotation(a, b):
    """True bila b adalah rotasi (siklik) dari a, selain rotasi 0."""
    n = len(a)
    if sorted(a) != sorted(b):
        return False, None
    for k in range(1, n):
        if [a[(i + k) % n] for i in range(n)] == b:
            return True, k
    return False, None


def adjacent_swap(a, b):
    """Bila b = a dengan tepat dua posisi bersebelahan ditukar, kembalikan posisinya."""
    diff = [i for i in range(len(a)) if a[i] != b[i]]
    if len(diff) == 2 and diff[1] - diff[0] == 1:
        i, j = diff
        if a[i] == b[j] and a[j] == b[i]:
            return i
    return None


def n_moved(a, b):
    return sum(1 for i in range(len(a)) if a[i] != b[i])


def value_shift(a, b, cols=None):
    """Bila b diperoleh dengan menggeser setiap NILAI indeks a sebesar k, kembalikan k."""
    c = cols or len(a)
    for k in range(1, c):
        if all((v + k) % c == w for v, w in zip(a, b)):
            return k
    return None


def positional_shift(recovered_pt, true_pt, max_shift=8):
    """Bila plaintext hasil hanyalah plaintext asli yang tergeser d posisi, kembalikan d."""
    for d in range(1, max_shift + 1):
        if recovered_pt[d:] == true_pt[:len(true_pt) - d]:
            return d
        if true_pt[d:] == recovered_pt[:len(recovered_pt) - d]:
            return -d
    return None


def decrypt_with_order(ciphertext, order):
    """Dekripsi memakai urutan kolom (bukan string kunci)."""
    key = "".join(chr(ord('A') + order.index(c)) for c in range(len(order)))
    assert transposition._column_order(key) == order, (key, order)
    return transposition.decrypt(ciphertext, key)


def last_full_row_boundary(length, cols):
    """Indeks awal baris terakhir yang TIDAK penuh (None bila grid penuh)."""
    rem = length % cols
    if rem == 0:
        return None
    return length - rem


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    pool = attack_plaintext_pool()
    with open(IN_CSV, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    target = [r for r in rows
              if r["success"] == "False" and r["readable"] == "True"
              and int(r["length"]) in LENGTHS]

    out = []
    for r in target:
        length = int(r["length"])
        trial = int(r["trial"])
        pt, ct, keys = rebuild_trial(length, trial, pool)
        true_order = list(keys["transposition_order"])
        rec_order = order_from_digits(r["recovered_order"])

        rec_pt = decrypt_with_order(ct, rec_order)
        diff_pos = [i for i in range(min(len(rec_pt), len(pt)))
                    if rec_pt[i] != pt[i]]
        n_diff = len(diff_pos)

        rot_ok, rot_k = is_rotation(true_order, rec_order)
        swap_at = adjacent_swap(true_order, rec_order)
        vshift = value_shift(true_order, rec_order, TRANS_COLS)
        pshift = positional_shift(rec_pt, pt)
        boundary = last_full_row_boundary(length, TRANS_COLS)
        rem = length % TRANS_COLS

        # D1: apakah semua huruf berbeda ada di baris terakhir tak penuh?
        if boundary is None:
            in_last_row = None
        else:
            in_last_row = all(i >= boundary for i in diff_pos) if diff_pos else True

        # D4: identik kecuali di baris terakhir tak penuh
        if boundary is None:
            same_except_last = (rec_pt == pt)
        else:
            same_except_last = rec_pt[:boundary] == pt[:boundary]

        out.append({
            "length": length, "trial": trial,
            "len_mod_6": rem,
            "true_order": "".join(map(str, true_order)),
            "recovered_order": "".join(map(str, rec_order)),
            "similarity": r["similarity"],
            "n_huruf_berbeda": n_diff,
            "posisi_min": min(diff_pos) if diff_pos else "",
            "posisi_maks": max(diff_pos) if diff_pos else "",
            "batas_baris_terakhir": "" if boundary is None else boundary,
            "semua_beda_di_baris_terakhir": in_last_row,
            "identik_kecuali_baris_terakhir": same_except_last,
            "rotasi": rot_ok, "rotasi_k": "" if rot_k is None else rot_k,
            "tukar_kolom_bersebelahan": swap_at is not None,
            "posisi_tukar": "" if swap_at is None else swap_at,
            "jumlah_kolom_berpindah": n_moved(true_order, rec_order),
            "geser_nilai_kolom_k": ("" if vshift is None else vshift),
            "geser_posisi_plaintext_d": ("" if pshift is None else pshift),
        })

    with open(os.path.join(OUT_DIR, "analisis_a2_transposisi.csv"), "w",
              newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(out[0]))
        w.writeheader()
        w.writerows(out)

    # ---------------- ringkasan ----------------
    L = []
    n = len(out)
    L.append("ANALISIS KEGAGALAN A2 (3B transposisi): success=False, readable=True")
    L.append("Sumber   : {}".format(IN_CSV))
    L.append("Panjang  : {}".format(", ".join(map(str, LENGTHS))))
    L.append("Jumlah percobaan yang dianalisis: {}".format(n))
    L.append("")

    all_3B = [r for r in rows if int(r["length"]) in LENGTHS]
    L.append("Tabel 1. Sebaran per panjang teks")
    L.append("{:>8} {:>8} {:>10} {:>12} {:>14}".format(
        "panjang", "mod 6", "total uji", "gagal+baca", "persen"))
    for ln in LENGTHS:
        tot = sum(1 for r in all_3B if int(r["length"]) == ln)
        k = sum(1 for r in out if r["length"] == ln)
        L.append("{:>8} {:>8} {:>10} {:>12} {:>13.1f}%".format(
            ln, ln % TRANS_COLS, tot, k, 100.0 * k / tot if tot else 0.0))
    L.append("")

    def pct(pred):
        k = sum(1 for r in out if pred(r))
        return k, (100.0 * k / n if n else 0.0)

    L.append("Tabel 2. Pemeriksaan tiap dugaan ({} percobaan)".format(n))
    checks = [
        ("D1 semua huruf beda di baris terakhir tak penuh",
         lambda r: r["semua_beda_di_baris_terakhir"] is True),
        ("D2 urutan hasil = rotasi urutan asli", lambda r: r["rotasi"] is True),
        ("D3 urutan hasil = tukar dua kolom bersebelahan",
         lambda r: r["tukar_kolom_bersebelahan"] is True),
        ("D4 plaintext identik kecuali baris terakhir tak penuh",
         lambda r: r["identik_kecuali_baris_terakhir"] is True),
        ("D6 urutan hasil = geser siklik NILAI indeks kolom",
         lambda r: r["geser_nilai_kolom_k"] != ""),
        ("D7 plaintext hasil = plaintext asli tergeser d posisi",
         lambda r: r["geser_posisi_plaintext_d"] != ""),
    ]
    for label, pred in checks:
        k, p = pct(pred)
        L.append("  {:<52} {:>3}/{:<3} = {:>5.1f}%".format(label, k, n, p))
    L.append("")

    diffs = [r["n_huruf_berbeda"] for r in out]
    L.append("Jumlah huruf berbeda: min={} maks={} median={} rata2={:.1f}".format(
        min(diffs), max(diffs), statistics.median(diffs), statistics.mean(diffs)))
    moved = [r["jumlah_kolom_berpindah"] for r in out]
    L.append("Jumlah kolom berpindah: min={} maks={} median={}".format(
        min(moved), max(moved), statistics.median(moved)))
    L.append("")

    L.append("Tabel 3. Sebaran panjang mod 6 pada kegagalan")
    bym = {}
    for r in out:
        bym[r["len_mod_6"]] = bym.get(r["len_mod_6"], 0) + 1
    for k in sorted(bym):
        L.append("  mod 6 = {} : {} percobaan".format(k, bym[k]))
    L.append("")

    L.append("Tiga contoh:")
    for r in out[:3]:
        L.append("  panjang {} percobaan {} (mod 6 = {})".format(
            r["length"], r["trial"], r["len_mod_6"]))
        L.append("    urutan asli  : {}".format(r["true_order"]))
        L.append("    urutan hasil : {}".format(r["recovered_order"]))
        L.append("    huruf berbeda: {} (posisi {}..{}), batas baris terakhir {}".format(
            r["n_huruf_berbeda"], r["posisi_min"], r["posisi_maks"],
            r["batas_baris_terakhir"]))
        L.append("    rotasi={} tukar_bersebelahan={} identik_kecuali_baris_terakhir={}".format(
            r["rotasi"], r["tukar_kolom_bersebelahan"],
            r["identik_kecuali_baris_terakhir"]))
        L.append("    geser nilai kolom k={}  geser posisi plaintext d={}".format(
            r["geser_nilai_kolom_k"], r["geser_posisi_plaintext_d"]))
    L.append("")

    d1k, d1p = pct(lambda r: r["semua_beda_di_baris_terakhir"] is True)
    d2k, d2p = pct(lambda r: r["rotasi"] is True)
    d3k, d3p = pct(lambda r: r["tukar_kolom_bersebelahan"] is True)
    d4k, d4p = pct(lambda r: r["identik_kecuali_baris_terakhir"] is True)
    d6k, d6p = pct(lambda r: r["geser_nilai_kolom_k"] != "")
    d7k, d7p = pct(lambda r: r["geser_posisi_plaintext_d"] != "")

    def verdict(p):
        if p >= 95.0:
            return "didukung"
        if p <= 5.0:
            return "tidak didukung"
        return "sebagian"

    L.append("KESIMPULAN (berdasarkan angka di atas, tanpa tambahan tafsir)")
    L.append("  D1 huruf beda menumpuk di baris terakhir : {} ({}/{} = {:.1f}%)".format(
        verdict(d1p), d1k, n, d1p))
    L.append("  D2 rotasi urutan kolom                   : {} ({}/{} = {:.1f}%)".format(
        verdict(d2p), d2k, n, d2p))
    L.append("  D3 tukar dua kolom bersebelahan          : {} ({}/{} = {:.1f}%)".format(
        verdict(d3p), d3k, n, d3p))
    L.append("  D4 identik kecuali baris terakhir        : {} ({}/{} = {:.1f}%)".format(
        verdict(d4p), d4k, n, d4p))
    nonzero = [k for k in sorted(bym) if k != 0]
    mods = sorted({ln % TRANS_COLS for ln in LENGTHS})
    L.append("  D5 kaitan dengan panjang mod 6           : tidak dapat dipisahkan; "
             "keempat panjang yang diuji hanya mencakup mod 6 = {} "
             "(kegagalan muncul pada mod 6 = {}), tidak ada panjang "
             "dengan mod 6 = 0 pada data ini".format(
                 ", ".join(map(str, mods)), ", ".join(map(str, nonzero)) or "-"))
    L.append("  D6 geser siklik nilai indeks kolom       : {} ({}/{} = {:.1f}%)".format(
        verdict(d6p), d6k, n, d6p))
    L.append("  D7 plaintext tergeser d posisi utuh      : {} ({}/{} = {:.1f}%)".format(
        verdict(d7p), d7k, n, d7p))
    ds = {}
    for r in out:
        if r["geser_posisi_plaintext_d"] != "":
            ds[r["geser_posisi_plaintext_d"]] = ds.get(
                r["geser_posisi_plaintext_d"], 0) + 1
    L.append("     sebaran d: {}".format(
        ", ".join("d={}: {}".format(k, ds[k]) for k in sorted(ds))))

    text = "\n".join(L)
    with open(os.path.join(OUT_DIR, "analisis_a2_transposisi.txt"), "w",
              encoding="utf-8") as f:
        f.write(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
