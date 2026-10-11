"""Analisis simpangan baku avalanche kunci transposisi (skenario 3 dan 6).

Mereproduksi persis pengukuran key avalanche di ``main_comparison.py``
(seed 2027, 10 percobaan, plaintext acuan 1000 huruf) lalu mencatat per
percobaan: posisi huruf kunci yang diganti, huruf asli dan penggantinya,
urutan kolom sebelum/sesudah, jumlah kolom yang berpindah posisi, jarak
Kendall tau, dan avalanche (%).

Dugaan yang diperiksa: simpangan baku avalanche kunci yang besar disebabkan
oleh beragamnya "besar" perubahan urutan kolom, sehingga avalanche berkorelasi
dengan jumlah kolom yang berpindah posisi.

Uji kepekaan 200 percobaan (seed 2027) HANYA dilaporkan sebagai pembanding;
angka yang dipakai paper tetap 10 percobaan.

Keluaran: hasil/analisis_tambahan/avalanche_kunci_transposisi.csv
          hasil/analisis_tambahan/avalanche_kunci_transposisi.txt

    python analisis_avalanche_kunci_transposisi.py
"""
import csv
import math
import os
import random
import statistics

import algorithms
import evaluation as ev
import main_comparison as mc
import sample_data
import transposition
from algorithms import ALPHABET

SEED_KEY = 2027
TRIALS_PAPER = 10
TRIALS_SENS = 200
REFERENCE_SIZE = 1000
OUT_DIR = os.path.join("hasil", "analisis_tambahan")
SCENARIO_NAMES = ("3. Transposisi Kolom", "6. Hill + Transposisi")


def kendall_tau_distance(a, b):
    """Jumlah pasangan diskordan (jarak Kendall tau) antara dua permutasi."""
    pos_b = {v: i for i, v in enumerate(b)}
    n = len(a)
    d = 0
    for i in range(n):
        for j in range(i + 1, n):
            if (pos_b[a[i]] - pos_b[a[j]]) < 0:
                d += 1
    return d


def pearson(xs, ys):
    n = len(xs)
    mx, my = statistics.mean(xs), statistics.mean(ys)
    sx = math.sqrt(sum((x - mx) ** 2 for x in xs))
    sy = math.sqrt(sum((y - my) ** 2 for y in ys))
    if sx == 0 or sy == 0:
        return None
    return sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / (sx * sy)


def flip_stream(key, trials, seed):
    """Reproduksi aliran bilangan acak _flip_key_string(require_order_change=True).

    Sama dengan yang dipakai evaluation.key_avalanche_effect_stats: tiap
    percobaan menarik satu posisi lalu huruf pengganti sampai urutan kolom
    berubah.
    """
    random.seed(seed)
    base_order = transposition._column_order(key)
    out = []
    for _ in range(trials):
        position = random.randrange(len(key))
        original = key[position]
        while True:
            replacement = random.choice(ALPHABET)
            if replacement == original:
                continue
            trial = list(key)
            trial[position] = replacement
            if transposition._column_order("".join(trial)) == base_order:
                continue
            break
        out.append((position, original, replacement, "".join(trial)))
    return out


def scenario_by_name(name):
    for s in algorithms.SCENARIOS:
        if s.name == name:
            return s
    raise KeyError(name)


def variant_with_transposition_key(scenario, new_key):
    return algorithms._build_scenario(
        scenario.name, scenario.components,
        vigenere_key=scenario._vigenere_key,
        hill_matrix=scenario._hill_matrix,
        hill_inverse=scenario._hill_inverse,
        transposition_key=new_key)


def measure(scenario, text, flips):
    base_ct = scenario.encrypt(text)
    base_order = transposition._column_order(scenario._transposition_key)
    rows = []
    for position, original, replacement, new_key in flips:
        variant = variant_with_transposition_key(scenario, new_key)
        ct2 = variant.encrypt(text)
        aval = ev._difference_percentage(base_ct, ct2)
        new_order = transposition._column_order(new_key)
        moved = sum(1 for i in range(len(base_order))
                    if base_order[i] != new_order[i])
        rows.append({
            "posisi": position, "huruf_asli": original,
            "huruf_pengganti": replacement,
            "kunci_baru": new_key,
            "urutan_sebelum": "".join(map(str, base_order)),
            "urutan_sesudah": "".join(map(str, new_order)),
            "kolom_berpindah": moved,
            "kendall_tau": kendall_tau_distance(base_order, new_order),
            "avalanche_persen": round(aval, 4),
        })
    return rows


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    plaintexts = sample_data.build_sample_sets(mc.SIZES, mc.SAMPLES_PER_SIZE)
    text = plaintexts[REFERENCE_SIZE]
    if isinstance(text, (list, tuple)):
        text = text[0]

    all_rows = []
    L = []
    L.append("ANALISIS SIMPANGAN BAKU AVALANCHE KUNCI TRANSPOSISI")
    L.append("Skenario : {}".format(", ".join(SCENARIO_NAMES)))
    L.append("Seed     : {} (sama dengan main_comparison.AVALANCHE_SEED_KEY)".format(SEED_KEY))
    L.append("Plaintext: acuan {} huruf".format(REFERENCE_SIZE))
    L.append("")

    summary = {}
    for name in SCENARIO_NAMES:
        scenario = scenario_by_name(name)
        key = scenario._transposition_key
        flips = flip_stream(key, TRIALS_PAPER, SEED_KEY)
        rows = measure(scenario, text, flips)
        for r in rows:
            r["skenario"] = name
            r["jumlah_percobaan"] = TRIALS_PAPER
        all_rows.extend(rows)

        avs = [r["avalanche_persen"] for r in rows]
        moved = [r["kolom_berpindah"] for r in rows]
        taus = [r["kendall_tau"] for r in rows]
        mean, sd = ev._mean_stdev(avs)
        summary[name] = (round(mean, 4), round(sd, 4))

        L.append("=" * 70)
        L.append("{}  (kunci transposisi '{}')".format(name, key))
        L.append("=" * 70)
        L.append("{:>3} {:>4} {:>4} {:>4} {:>9} {:>9} {:>7} {:>8} {:>10}".format(
            "no", "pos", "asli", "ganti", "sebelum", "sesudah", "pindah",
            "kendall", "avalanche"))
        for i, r in enumerate(rows, 1):
            L.append("{:>3} {:>4} {:>4} {:>4} {:>9} {:>9} {:>7} {:>8} {:>9.4f}%".format(
                i, r["posisi"], r["huruf_asli"], r["huruf_pengganti"],
                r["urutan_sebelum"], r["urutan_sesudah"], r["kolom_berpindah"],
                r["kendall_tau"], r["avalanche_persen"]))
        L.append("")
        L.append("  rata-rata avalanche   : {:.4f}%".format(mean))
        L.append("  simpangan baku        : {:.4f}%".format(sd))
        L.append("  rentang avalanche     : {:.4f}% .. {:.4f}%".format(
            min(avs), max(avs)))
        L.append("  kolom berpindah       : min {} maks {} (nilai: {})".format(
            min(moved), max(moved), ", ".join(map(str, moved))))
        L.append("  kendall tau           : min {} maks {}".format(
            min(taus), max(taus)))
        r_moved = pearson(moved, avs)
        r_tau = pearson(taus, avs)
        L.append("  korelasi Pearson (kolom berpindah vs avalanche): {}".format(
            "tidak terdefinisi (varians 0)" if r_moved is None
            else "{:.4f}".format(r_moved)))
        L.append("  korelasi Pearson (kendall tau vs avalanche)    : {}".format(
            "tidak terdefinisi (varians 0)" if r_tau is None
            else "{:.4f}".format(r_tau)))

        # uji kepekaan 200 percobaan
        flips200 = flip_stream(key, TRIALS_SENS, SEED_KEY)
        rows200 = measure(scenario, text, flips200)
        avs200 = [r["avalanche_persen"] for r in rows200]
        moved200 = [r["kolom_berpindah"] for r in rows200]
        m200, sd200 = ev._mean_stdev(avs200)
        r200 = pearson(moved200, avs200)
        L.append("  UJI KEPEKAAN {} percobaan (bukan angka paper):".format(TRIALS_SENS))
        L.append("    rata-rata {:.4f}%  simpangan baku {:.4f}%".format(m200, sd200))
        L.append("    korelasi (kolom berpindah vs avalanche): {}".format(
            "tidak terdefinisi" if r200 is None else "{:.4f}".format(r200)))
        L.append("")
        summary[name] = (round(mean, 4), round(sd, 4), r_moved, r_tau,
                         round(m200, 4), round(sd200, 4), r200)

        for r in rows200:
            r["skenario"] = name
            r["jumlah_percobaan"] = TRIALS_SENS
        all_rows.extend(rows200)

    # verifikasi terhadap avalanche.csv
    L.append("=" * 70)
    L.append("VERIFIKASI terhadap hasil/avalanche.csv")
    L.append("=" * 70)
    path = os.path.join("hasil", "avalanche.csv")
    ok_all = True
    if os.path.exists(path):
        with open(path, newline="", encoding="utf-8") as f:
            ref = {r["Skenario"]: r for r in csv.DictReader(f)}
        for name in SCENARIO_NAMES:
            got_mean, got_sd = summary[name][0], summary[name][1]
            exp_mean = float(ref[name]["Avalanche Kunci (%)"])
            exp_sd = float(ref[name]["Stdev Kunci (%)"])
            ok = (abs(got_mean - exp_mean) < 1e-9 and abs(got_sd - exp_sd) < 1e-9)
            ok_all = ok_all and ok
            L.append("  {:<24} mean {} vs {} | stdev {} vs {} -> {}".format(
                name, got_mean, exp_mean, got_sd, exp_sd,
                "COCOK" if ok else "BEDA"))
    else:
        L.append("  (hasil/avalanche.csv tidak ditemukan)")
        ok_all = False
    L.append("")

    L.append("KESIMPULAN (hanya dari angka di atas)")
    for name in SCENARIO_NAMES:
        mean, sd, r_moved, r_tau, m200, sd200, r200 = summary[name]
        if r_moved is None:
            verd = ("tidak dapat diuji: jumlah kolom berpindah tidak "
                    "bervariasi pada 10 percobaan")
        elif abs(r_moved) >= 0.7:
            verd = "didukung (|r| >= 0,7)"
        elif abs(r_moved) >= 0.3:
            verd = "sebagian (0,3 <= |r| < 0,7)"
        else:
            verd = "tidak didukung (|r| < 0,3)"
        L.append("  {}".format(name))
        L.append("    avalanche 10 percobaan : {:.4f}% +/- {:.4f}%".format(mean, sd))
        L.append("    dugaan 'simpangan baku besar karena variasi besar perubahan "
                 "urutan kolom': {}".format(verd))
        L.append("    korelasi kolom berpindah vs avalanche : {}".format(
            "n/a" if r_moved is None else "{:.4f}".format(r_moved)))
        L.append("    korelasi kendall tau vs avalanche     : {}".format(
            "n/a" if r_tau is None else "{:.4f}".format(r_tau)))
        L.append("    uji kepekaan 200 percobaan            : {:.4f}% +/- {:.4f}% "
                 "(korelasi {})".format(
                     m200, sd200, "n/a" if r200 is None else "{:.4f}".format(r200)))
    L.append("")
    L.append("Reproduksi angka paper (10 percobaan): {}".format(
        "SEMUA COCOK" if ok_all else "ADA YANG BEDA - periksa"))

    fields = ["skenario", "jumlah_percobaan", "posisi", "huruf_asli",
              "huruf_pengganti", "kunci_baru", "urutan_sebelum",
              "urutan_sesudah", "kolom_berpindah", "kendall_tau",
              "avalanche_persen"]
    with open(os.path.join(OUT_DIR, "avalanche_kunci_transposisi.csv"), "w",
              newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in all_rows:
            w.writerow({k: r[k] for k in fields})

    text_out = "\n".join(L)
    with open(os.path.join(OUT_DIR, "avalanche_kunci_transposisi.txt"), "w",
              encoding="utf-8") as f:
        f.write(text_out + "\n")
    print(text_out)


if __name__ == "__main__":
    main()
