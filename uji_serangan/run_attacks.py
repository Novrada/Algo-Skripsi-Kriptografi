"""Program utama uji serangan (Tahap 3): menjalankan serangan 3A-3F.

Letakkan file ini dan folder ``serangan/`` di folder yang sama dengan
``algorithms.py``, lalu jalankan::

    python run_attacks.py                 # semua serangan, 50 kunci acak
    python run_attacks.py --keys 5        # uji cepat (5 kunci)
    python run_attacks.py --only 3A,3E    # hanya serangan tertentu

Keluaran (folder ``hasil/serangan/``):

* ``serangan_<ID>.csv``        : satu baris per percobaan (data mentah)
* ``ringkasan_serangan.csv``   : success rate, waktu median/maks, jumlah
                                 kandidat yang dicoba, per serangan & parameter
* ``info_eksperimen.txt``      : seed, sumber korpus referensi, versi Python

Model penyerang:

* 3A, 3B, 3F : ciphertext-only (hanya memegang badan ciphertext).
* 3C, 3D, 3E : known-plaintext (memegang satu pasangan plaintext-ciphertext).
* Algoritma dan skema padding dianggap publik (prinsip Kerckhoffs).
* Panjang kunci Vigenere TIDAK diketahui (dicari 1..20).  Jumlah kolom
  transposisi dianggap diketahui (6), sesuai kunci pada skripsi.

Keberhasilan 3C-3E diukur secara fungsional: kunci hasil serangan harus
mendekripsi pesan LAIN (held-out, 301 huruf) dengan benar.
"""

import argparse
import csv
import difflib
import math
import os
import platform
import random
import statistics
import time

import evaluation as ev
from serangan import classical_attacks as ca
from serangan import linear_attacks as la
from serangan.common import Timer, build_scenario, random_keys
from serangan.lang_model import (LanguageModel, attack_plaintext_pool,
                                 reference_text)

# ---------------------------------------------------------------------------
# Konfigurasi
# ---------------------------------------------------------------------------
OUTPUT_DIR = os.path.join("hasil", "serangan")
SEED = 2026
N_KEYS = 50
VIG_LEN = 5          # sama dengan kunci skripsi (KUNCI)
HILL_N = 3
TRANS_COLS = 6       # sama dengan kunci skripsi (KRIPTO)
MAX_PERIOD = 20      # batas pencarian panjang kunci Vigenere
HELDOUT_LEN = 301    # pesan uji fungsional (bukan kelipatan 3 maupun 6)

LENGTHS = {
    "3A": [50, 100, 200, 500, 1000],          # panjang ciphertext
    "3B": [50, 100, 200, 500, 1000],
    "3C": [9, 12, 15, 18, 24, 30, 60],       # panjang known-plaintext
    "3D": [15, 30, 45, 60, 90, 120, 150, 300],
    "3E-HT": [60, 150, 300, 1000],           # panjang pesan known-plaintext
    "3E-VHT": [60, 150, 300, 1000],
    "3F": [200, 500, 1000],
}

SCENARIO_OF = {
    "3A": ["Vigenere"],
    "3B": ["Transposisi"],
    "3C": ["Hill"],
    "3D": ["Vigenere", "Hill"],
    "3E-HT": ["Hill", "Transposisi"],
    "3E-VHT": ["Vigenere", "Hill", "Transposisi"],
    "3F": ["Vigenere", "Transposisi"],
}

MODEL_OF = {k: ("ciphertext-only" if k in ("3A", "3B", "3F")
                else "known-plaintext") for k in SCENARIO_OF}


def nominal_bits(components):
    parts = {"Vigenere": ev.key_space_vigenere(VIG_LEN),
             "Hill": ev.key_space_hill(HILL_N),
             "Transposisi": ev.key_space_transposition(TRANS_COLS)}
    total = 1
    for c in components:
        total *= parts[c]
    return math.log2(total)


# ---------------------------------------------------------------------------
# Satu percobaan per serangan
# ---------------------------------------------------------------------------
NEAR_THRESHOLD = 0.95   # batas "plaintext terbaca" (kemiripan urutan huruf)


def similarity(recovered, truth):
    """Kemiripan urutan (difflib ratio, 0-1) antara plaintext hasil dan asli.

    Dipakai untuk serangan ciphertext-only: hasil yang tergeser 1-2 huruf
    (mis. urutan kolom yang merupakan rotasi urutan benar) tetap TERBACA
    walaupun tidak identik posisi-per-posisi.
    """
    return difflib.SequenceMatcher(None, recovered, truth,
                                   autojunk=False).ratio()


def _sample(pool, rng, length):
    start = rng.randrange(0, len(pool) - length)
    return pool[start:start + length]


def run_trial(attack_id, length, trial, pool, lm):
    rng = random.Random(SEED * 100003 + trial * 101 + length)
    keys = random_keys(rng, VIG_LEN, HILL_N, TRANS_COLS)
    scenario = build_scenario(SCENARIO_OF[attack_id], keys)
    pt = _sample(pool, rng, length)
    heldout = _sample(pool, rng, HELDOUT_LEN)
    body = scenario.cipher_body(pt)
    row = {"attack": attack_id, "scenario": scenario.name,
           "model": MODEL_OF[attack_id], "length": length, "trial": trial,
           "true_vigenere": keys["vigenere"] if "Vigenere" in
           SCENARIO_OF[attack_id] else "",
           "true_order": "".join(map(str, keys["transposition_order"]))
           if "Transposisi" in SCENARIO_OF[attack_id] else ""}

    if attack_id == "3A":
        with Timer() as t:
            r = ca.attack_vigenere(body, lm, MAX_PERIOD)
        sim = similarity(r["plaintext"], pt)
        row.update(success=r["plaintext"] == pt, similarity=round(sim, 4),
                   readable=sim >= NEAR_THRESHOLD,
                   recovered_key=r["key"], recovered_period=r["period"],
                   key_exact=r["key"] == keys["vigenere"],
                   candidates_tried=r["candidates_tried"])

    elif attack_id == "3B":
        with Timer() as t:
            r = ca.attack_transposition(body, lm, (TRANS_COLS,))
        sim = similarity(r["plaintext"], pt)
        row.update(success=r["plaintext"] == pt, similarity=round(sim, 4),
                   readable=sim >= NEAR_THRESHOLD,
                   recovered_order="".join(map(str, r["order"])),
                   key_exact=tuple(r["order"]) == keys["transposition_order"],
                   candidates_tried=r["candidates_tried"])

    elif attack_id == "3F":
        with Timer() as t:
            r = ca.attack_vigenere_transposition(body, lm, TRANS_COLS,
                                                 MAX_PERIOD)
        sim = similarity(r["plaintext"], pt)
        row.update(success=r["plaintext"] == pt, similarity=round(sim, 4),
                   readable=sim >= NEAR_THRESHOLD,
                   recovered_key=r["key"], recovered_period=r["period"],
                   recovered_order="".join(map(str, r["order"])),
                   key_exact=(r["key"] == keys["vigenere"] and
                              tuple(r["order"]) ==
                              keys["transposition_order"]),
                   candidates_tried=r["candidates_tried"])

    elif attack_id in ("3C", "3D"):
        with Timer() as t:
            if attack_id == "3C":
                r = la.attack_hill_kpa(pt, body)
            else:
                r = la.attack_vigenere_hill_kpa(pt, body, MAX_PERIOD)
        ok = False
        key_exact = False
        vig = ""
        if r:
            hb = scenario.cipher_body(heldout)
            ok = la.decrypt_with(hb, len(heldout), r["K"], r["b"],
                                 r["period"]) == heldout
            key_exact = r["K"] == keys["hill"]
            if attack_id == "3D":
                vig = la.recover_vigenere_key(r["K"], r["b"], r["period"],
                                              VIG_LEN) or ""
                key_exact = key_exact and vig == keys["vigenere"]
        row.update(success=ok, key_exact=key_exact,
                   recovered_period=r["period"] if r else "",
                   recovered_key=vig,
                   candidates_tried=r["candidates_tried"] if r else 0)

    elif attack_id in ("3E-HT", "3E-VHT"):
        with Timer() as t:
            r = la.attack_with_transposition_kpa(
                pt, body, with_vigenere=(attack_id == "3E-VHT"),
                n_cols=TRANS_COLS, max_period=MAX_PERIOD, full_sweep=True)
        hb = scenario.cipher_body(heldout)
        valid = [c for c in r["candidates"]
                 if la.decrypt_with(hb, len(heldout), c["K"], c["b"],
                                    c["period"], c["order"]) == heldout]
        exact = any(tuple(c["order"]) == keys["transposition_order"] and
                    c["K"] == keys["hill"] for c in valid)
        row.update(success=bool(valid), key_exact=exact,
                   n_consistent=len(r["candidates"]),
                   n_equivalent_valid=len(valid),
                   first_hit_index=r["first_hit_index"] or "",
                   candidates_tried=r["candidates_tried"])
    else:
        raise ValueError(attack_id)

    row["time_s"] = t.seconds
    return row


# ---------------------------------------------------------------------------
# Ringkasan
# ---------------------------------------------------------------------------
def summarize(rows):
    out = []
    keys = sorted({(r["attack"], r["length"]) for r in rows},
                  key=lambda k: (k[0], k[1]))
    for attack_id, length in keys:
        rs = [r for r in rows if r["attack"] == attack_id and
              r["length"] == length]
        times = [r["time_s"] for r in rs]
        tried = [r["candidates_tried"] for r in rs if r["candidates_tried"]]
        med_tried = statistics.median(tried) if tried else 0
        out.append({
            "Serangan": attack_id,
            "Skenario": rs[0]["scenario"],
            "Model": rs[0]["model"],
            "Panjang (huruf)": length,
            "Jumlah kunci": len(rs),
            "Success rate (%)": round(100 * sum(r["success"] for r in rs)
                                      / len(rs), 1),
            "Terbaca >=95% (%)": round(100 * sum(bool(r.get("readable", r["success"])) for r in rs) / len(rs), 1),
            "Kemiripan median": round(statistics.median(r.get("similarity", 1.0 if r["success"] else 0.0) for r in rs), 4),
            "Kunci persis (%)": round(100 * sum(bool(r.get("key_exact"))
                                                for r in rs) / len(rs), 1),
            "Waktu median (s)": round(statistics.median(times), 4),
            "Waktu maks (s)": round(max(times), 4),
            "Kandidat dicoba (median)": med_tried,
            "Kerja efektif (bit)": round(math.log2(med_tried), 1)
            if med_tried else "",
            "Ruang kunci nominal (bit)":
                round(nominal_bits(SCENARIO_OF[attack_id]), 1),
        })
    return out


def write_csv(path, rows):
    fields = []
    for r in rows:
        for k in r:
            if k not in fields:
                fields.append(k)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--keys", type=int, default=N_KEYS)
    ap.add_argument("--only", type=str, default="")
    args = ap.parse_args()
    selected = [a.strip() for a in args.only.split(",") if a.strip()] \
        or list(SCENARIO_OF)
    for a in selected:
        if a not in SCENARIO_OF:
            raise SystemExit("ID serangan tidak dikenal: " + a)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ref, ref_src = reference_text()
    lm = LanguageModel(ref, n=3)
    pool = attack_plaintext_pool()

    with open(os.path.join(OUTPUT_DIR, "info_eksperimen.txt"), "w",
              encoding="utf-8") as f:
        f.write("Tanggal       : {}\n".format(time.strftime("%Y-%m-%d %H:%M")))
        f.write("Python        : {}\n".format(platform.python_version()))
        f.write("Platform      : {}\n".format(platform.platform()))
        f.write("Prosesor      : {}\n".format(platform.processor()))
        f.write("Seed          : {}\n".format(SEED))
        f.write("Jumlah kunci  : {}\n".format(args.keys))
        f.write("Korpus ref.   : {} ({} huruf)\n".format(ref_src, len(ref)))
        f.write("Pool plaintext: {} huruf\n".format(len(pool)))

    print("Korpus referensi:", ref_src, "-", len(ref), "huruf")
    print("Pool plaintext  :", len(pool), "huruf\n")

    all_rows = []
    for attack_id in selected:
        rows = []
        for length in LENGTHS[attack_id]:
            t0 = time.perf_counter()
            for trial in range(args.keys):
                rows.append(run_trial(attack_id, length, trial, pool, lm))
            rs = rows[-args.keys:]
            print("  {:7s} panjang {:5d}: success {:5.1f}%  "
                  "waktu median {:.3f}s  ({:.1f}s total)".format(
                      attack_id, length,
                      100 * sum(r["success"] for r in rs) / len(rs),
                      statistics.median(r["time_s"] for r in rs),
                      time.perf_counter() - t0))
        write_csv(os.path.join(OUTPUT_DIR,
                               "serangan_{}.csv".format(attack_id)), rows)
        all_rows.extend(rows)

    summary = summarize(all_rows)
    write_csv(os.path.join(OUTPUT_DIR, "ringkasan_serangan.csv"), summary)
    print("\nHasil ditulis ke", OUTPUT_DIR)


if __name__ == "__main__":
    main()
