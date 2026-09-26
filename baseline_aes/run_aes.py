"""Program utama Baseline AES.

Mengukur AES-128 dan AES-256 dengan metrik yang sama (sejauh bisa dibandingkan)
dengan ketujuh skenario cipher klasik skripsi:

1. waktu enkripsi/dekripsi (protokol sama dengan skripsi: 3 sampel per ukuran,
   warm-up, 100 repetisi / 30 untuk 5000 karakter, ``time.perf_counter()``,
   gc dimatikan, semua nilai repetisi mentah disimpan),
2. avalanche effect level bit (ideal 50%),
3. avalanche level pesan (mode CBC, untuk diskusi mode operasi),
4. entropi Shannon level byte (dibandingkan acuan acak os.urandom, bukan 8,0),
5. Index of Coincidence level byte (ideal 1/256),
6. tabel perbandingan ternormalisasi (7 skenario klasik + AES-128 + AES-256).

Plaintext memakai ``sample_data.build_sample_sets`` dari kode skripsi sehingga
identik dengan plaintext yang dipakai pada pengujian 7 skenario klasik.

Jalankan dari folder induk proyek::

    python baseline_aes/run_aes.py

Keluaran ditulis ke ``hasil/aes/``.
"""

import csv
import gc
import math
import os
import platform
import random
import statistics
import sys
import time

from cryptography import __version__ as cryptography_version

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import sample_data  # noqa: E402

import aes_cipher  # noqa: E402
import aes_metrics  # noqa: E402

OUTPUT_DIR = os.path.join(ROOT, "hasil", "aes")
SIZES = [50, 100, 500, 1000, 5000]
SAMPLES_PER_SIZE = 3
REFERENCE_TIME_SIZE = 1000
STATISTIC_SIZE = 5000

SEED = 2026

WARMUP = 3
AVALANCHE_BIT_KEYS = 50
AVALANCHE_BIT_POSITIONS = 20
AVALANCHE_MESSAGE_TRIALS = 100
ENTROPY_RANDOM_TRIALS = 100
ENTROPY_RANDOM_BYTES = 5000

LOG2_26 = math.log2(26)
AVALANCHE_IDEAL_CLASSIC = 100.0 * 25.0 / 26.0
AZ = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

KEY_SPACE_BITS = {"AES-128": 128, "AES-256": 256}


def repeats_for(size):
    return 30 if size >= 5000 else 100


def _rng(offset):
    return random.Random(SEED + offset)


def _mean(values):
    return sum(values) / len(values)


def _stdev(values):
    return statistics.stdev(values) if len(values) > 1 else 0.0


def _iqr(values):
    q = statistics.quantiles(values, n=4)
    return q[2] - q[0]


def _write_dict_csv(path, rows):
    fields = []
    for r in rows:
        for k in r:
            if k not in fields:
                fields.append(k)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


# ---------------------------------------------------------------------------
# Persiapan kunci & IV
# ---------------------------------------------------------------------------
def build_keys():
    rng = _rng(0)
    keys = {}
    for variant in aes_cipher.VARIANTS:
        keys[variant] = {
            "key": aes_cipher.generate_key(variant, rng),
            "iv": aes_cipher.generate_iv(rng),
        }
    return keys


# ---------------------------------------------------------------------------
# 1. Uji kebenaran
# ---------------------------------------------------------------------------
def run_correctness(plaintext_sets, keys):
    for variant in aes_cipher.VARIANTS:
        key = keys[variant]["key"]
        iv = keys[variant]["iv"]
        for size, samples in plaintext_sets.items():
            for text in samples:
                pt = text.encode("ascii")
                ct = aes_cipher.encrypt_cbc(pt, key, iv)
                rec = aes_cipher.decrypt_cbc(ct, key, iv)
                if rec != pt:
                    raise AssertionError(
                        "roundtrip gagal: {} ukuran {}".format(variant, size))
    print("[1] decrypt(encrypt(x)) == x : OK (semua sampel, kedua varian)")


# ---------------------------------------------------------------------------
# 2. Waktu
# ---------------------------------------------------------------------------
def _time_samples(variant, key, iv, pt_bytes, repeat):
    ct = aes_cipher.encrypt_cbc(pt_bytes, key, iv)

    for _ in range(WARMUP):
        aes_cipher.encrypt_cbc(pt_bytes, key, iv)
        aes_cipher.decrypt_cbc(ct, key, iv)

    gc.disable()
    try:
        enc = []
        dec = []
        for _ in range(repeat):
            t0 = time.perf_counter()
            aes_cipher.encrypt_cbc(pt_bytes, key, iv)
            enc.append((time.perf_counter() - t0) * 1000.0)
        for _ in range(repeat):
            t0 = time.perf_counter()
            aes_cipher.decrypt_cbc(ct, key, iv)
            dec.append((time.perf_counter() - t0) * 1000.0)
    finally:
        gc.enable()
    return enc, dec


def run_time(plaintext_sets, keys):
    raw_rows = []
    summary_rows = []
    for variant in aes_cipher.VARIANTS:
        key = keys[variant]["key"]
        iv = keys[variant]["iv"]
        for size in SIZES:
            samples = plaintext_sets[size]
            repeat = repeats_for(size)
            enc_all = []
            dec_all = []
            for sample_idx, text in enumerate(samples):
                pt_bytes = text.encode("ascii")
                enc, dec = _time_samples(variant, key, iv, pt_bytes, repeat)
                for rep_idx, ms in enumerate(enc):
                    raw_rows.append({
                        "varian": variant, "ukuran": size,
                        "sampel_ke": sample_idx + 1,
                        "repetisi_ke": rep_idx + 1, "operasi": "enc",
                        "waktu_ms": round(ms, 9)})
                for rep_idx, ms in enumerate(dec):
                    raw_rows.append({
                        "varian": variant, "ukuran": size,
                        "sampel_ke": sample_idx + 1,
                        "repetisi_ke": rep_idx + 1, "operasi": "dec",
                        "waktu_ms": round(ms, 9)})
                enc_all.extend(enc)
                dec_all.extend(dec)
            for op, all_vals in (("enc", enc_all), ("dec", dec_all)):
                mean = _mean(all_vals)
                summary_rows.append({
                    "varian": variant, "ukuran": size, "operasi": op,
                    "mean_ms": round(mean, 6),
                    "stdev_ms": round(_stdev(all_vals), 6),
                    "median_ms": round(statistics.median(all_vals), 6),
                    "iqr_ms": round(_iqr(all_vals), 6),
                    "throughput_kar_per_ms": round(size / mean, 3)
                    if mean else 0.0})
    return raw_rows, summary_rows


# ---------------------------------------------------------------------------
# 3. Avalanche bit
# ---------------------------------------------------------------------------
def _avalanche_bit_variant(variant):
    rows = []
    n_keys = AVALANCHE_BIT_KEYS
    n_pos = AVALANCHE_BIT_POSITIONS
    key_bits = aes_cipher.KEY_SIZE[variant] * 8
    block_bits = aes_cipher.BLOCK_SIZE * 8

    rng = _rng(100 + list(aes_cipher.VARIANTS).index(variant))
    trial = 0
    for _ in range(n_keys):
        key = aes_cipher.generate_key(variant, rng)
        block = bytes(rng.randrange(256) for _ in range(aes_cipher.BLOCK_SIZE))
        c1 = aes_cipher.encrypt_ecb_block(block, key)
        for _ in range(n_pos):
            bit = rng.randrange(block_bits)
            c2 = aes_cipher.encrypt_ecb_block(aes_cipher.flip_bit(block, bit), key)
            diff = aes_cipher.differing_bits(c1, c2)
            rows.append({"varian": variant, "jenis": "plaintext",
                         "percobaan_ke": trial,
                         "bit_berbeda": diff,
                         "persen": round(diff / block_bits * 100, 4)})
            trial += 1

    rng = _rng(200 + list(aes_cipher.VARIANTS).index(variant))
    fixed_block = bytes(rng.randrange(256)
                        for _ in range(aes_cipher.BLOCK_SIZE))
    trial = 0
    for _ in range(n_keys):
        key = aes_cipher.generate_key(variant, rng)
        c1 = aes_cipher.encrypt_ecb_block(fixed_block, key)
        for _ in range(n_pos):
            bit = rng.randrange(key_bits)
            key2 = aes_cipher.flip_bit(key, bit)
            c2 = aes_cipher.encrypt_ecb_block(fixed_block, key2)
            diff = aes_cipher.differing_bits(c1, c2)
            rows.append({"varian": variant, "jenis": "kunci",
                         "percobaan_ke": trial,
                         "bit_berbeda": diff,
                         "persen": round(diff / block_bits * 100, 4)})
            trial += 1
    return rows


def run_avalanche_bit():
    rows = []
    for variant in aes_cipher.VARIANTS:
        rows.extend(_avalanche_bit_variant(variant))
    return rows


# ---------------------------------------------------------------------------
# 4. Avalanche pesan
# ---------------------------------------------------------------------------
def run_avalanche_message(plaintext_sets, keys):
    rows = []
    for variant in aes_cipher.VARIANTS:
        key = keys[variant]["key"]
        iv = keys[variant]["iv"]
        base_text = plaintext_sets[REFERENCE_TIME_SIZE][0]
        base_bytes = base_text.encode("ascii")
        c1 = aes_cipher.encrypt_cbc(base_bytes, key, iv)
        n = len(base_text)
        rng = _rng(300 + list(aes_cipher.VARIANTS).index(variant))
        for trial in range(AVALANCHE_MESSAGE_TRIALS):
            pos = rng.randrange(n)
            original = base_text[pos]
            replacement = rng.choice(AZ.replace(original, ""))
            changed = base_text[:pos] + replacement + base_text[pos + 1:]
            c2 = aes_cipher.encrypt_cbc(changed.encode("ascii"), key, iv)
            diff = sum(1 for a, b in zip(c1, c2) if a != b)
            rows.append({
                "varian": variant, "percobaan_ke": trial,
                "posisi_diubah": pos,
                "persen_byte_berbeda": round(diff / len(c1) * 100, 4)})
    return rows


# ---------------------------------------------------------------------------
# 5. Entropi & IC
# ---------------------------------------------------------------------------
def run_statistics(plaintext_sets, keys):
    ref_entropy = _mean([
        aes_metrics.shannon_entropy_bytes(os.urandom(ENTROPY_RANDOM_BYTES))
        for _ in range(ENTROPY_RANDOM_TRIALS)])
    text = plaintext_sets[STATISTIC_SIZE][0]
    pt_bytes = text.encode("ascii")
    rows = []
    for variant in aes_cipher.VARIANTS:
        key = keys[variant]["key"]
        iv = keys[variant]["iv"]
        ct = aes_cipher.encrypt_cbc(pt_bytes, key, iv)
        ent = aes_metrics.shannon_entropy_bytes(ct)
        ic = aes_metrics.index_of_coincidence_bytes(ct)
        rows.append({
            "varian": variant,
            "entropi_byte": round(ent, 6),
            "acuan_entropi_acak": round(ref_entropy, 6),
            "IC_byte": round(ic, 6),
            "rasio_IC": round(aes_metrics.ic_ratio_bytes(ic), 6)})
    return rows, ref_entropy


# ---------------------------------------------------------------------------
# 6. Tabel perbandingan ternormalisasi
# ---------------------------------------------------------------------------
def _read_classic_results():
    path = os.path.join(ROOT, "hasil", "hasil_perbandingan.csv")
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def build_comparison_table(time_summary, stat_rows, avalanche_rows):
    classic = _read_classic_results()
    enc_ms_by = {}
    for r in time_summary:
        if r["ukuran"] == REFERENCE_TIME_SIZE and r["operasi"] == "enc":
            enc_ms_by[r["varian"]] = r["mean_ms"]

    def avalanche_mean(variant, jenis):
        vals = [r["persen"] for r in avalanche_rows
                if r["varian"] == variant and r["jenis"] == jenis]
        return _mean(vals)

    stat_by = {r["varian"]: r for r in stat_rows}

    rows = []
    for r in classic:
        name = r["Skenario"]
        rows.append({
            "Skenario": name,
            "Waktu Enkripsi 1000 kar (ms)": round(float(r["Waktu Enkripsi (ms)"]), 6),
            "Entropi Ternormalisasi": round(
                float(r["Entropi Ciphertext (bit)"]) / LOG2_26, 6),
            "Rasio IC": round(float(r["IC Ciphertext"]) * 26, 6),
            "Avalanche Ternormalisasi": round(
                float(r["Avalanche Plaintext (%)"]) / AVALANCHE_IDEAL_CLASSIC, 6),
            "Ruang Kunci Nominal (bit)": round(float(r["Ruang Kunci (bit)"]), 2)})

    for variant in aes_cipher.VARIANTS:
        s = stat_by[variant]
        rows.append({
            "Skenario": variant,
            "Waktu Enkripsi 1000 kar (ms)": round(enc_ms_by[variant], 6),
            "Entropi Ternormalisasi": round(
                aes_metrics.normalized_entropy_byte(s["entropi_byte"]), 6),
            "Rasio IC": round(s["rasio_IC"], 6),
            "Avalanche Ternormalisasi": round(
                aes_metrics.normalized_avalanche_bit(
                    avalanche_mean(variant, "plaintext")), 6),
            "Ruang Kunci Nominal (bit)": KEY_SPACE_BITS[variant]})
    return rows


# ---------------------------------------------------------------------------
# 7. Info lingkungan
# ---------------------------------------------------------------------------
def _cpu_info():
    cpu = platform.processor() or ""
    if not cpu:
        try:
            with open("/proc/cpuinfo", encoding="utf-8") as f:
                for line in f:
                    if line.lower().startswith("model name"):
                        cpu = line.split(":", 1)[1].strip()
                        break
        except OSError:
            pass
    return cpu or platform.machine()


def write_info():
    lines = [
        "Tanggal           : {}".format(time.strftime("%Y-%m-%d %H:%M")),
        "Python            : {}".format(platform.python_version()),
        "cryptography      : {}".format(cryptography_version),
        "OS                : {}".format(platform.platform()),
        "CPU               : {}".format(_cpu_info()),
        "Seed              : {}".format(SEED),
        "Plaintext         : sample_data.build_sample_sets([50, 100, 500, 1000, 5000], 3)",
        "Protokol waktu    : 3 sampel, warm-up {}, {}x (30x utk 5000), gc off, perf_counter".format(
            WARMUP, repeats_for(REFERENCE_TIME_SIZE)),
        "Avalanche bit     : {} kunci x {} posisi = {} percobaan".format(
            AVALANCHE_BIT_KEYS, AVALANCHE_BIT_POSITIONS,
            AVALANCHE_BIT_KEYS * AVALANCHE_BIT_POSITIONS),
        "Avalanche pesan   : {} percobaan, 1000 karakter, CBC".format(
            AVALANCHE_MESSAGE_TRIALS),
        "Entropi acuan     : {}x {} byte os.urandom".format(
            ENTROPY_RANDOM_TRIALS, ENTROPY_RANDOM_BYTES),
    ]
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(os.path.join(OUTPUT_DIR, "info_lingkungan.txt"), "w",
              encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


# ---------------------------------------------------------------------------
# Titik masuk
# ---------------------------------------------------------------------------
def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print("Baseline AES: AES-128 & AES-256 (cryptography {})".format(
        cryptography_version))
    print()

    plaintext_sets = sample_data.build_sample_sets(SIZES, SAMPLES_PER_SIZE)
    keys = build_keys()

    print("[1] Uji kebenaran")
    run_correctness(plaintext_sets, keys)
    print()

    print("[2] Pengukuran waktu")
    raw_rows, time_summary = run_time(plaintext_sets, keys)
    for r in time_summary:
        if r["ukuran"] == REFERENCE_TIME_SIZE:
            print("  {:8s} {:4s}  {:5d} kar: mean {:.4f} ms | median {:.4f} ms".format(
                r["varian"], r["operasi"], r["ukuran"], r["mean_ms"],
                r["median_ms"]))
    _write_dict_csv(os.path.join(OUTPUT_DIR, "aes_waktu_mentah.csv"), raw_rows)
    _write_dict_csv(os.path.join(OUTPUT_DIR, "aes_waktu_ringkasan.csv"),
                    time_summary)
    print()

    print("[3] Avalanche bit (ECB, 1 blok)")
    avalanche_rows = run_avalanche_bit()
    _write_dict_csv(os.path.join(OUTPUT_DIR, "aes_avalanche_bit.csv"),
                    avalanche_rows)
    for variant in aes_cipher.VARIANTS:
        for jenis in ("plaintext", "kunci"):
            vals = [r["persen"] for r in avalanche_rows
                    if r["varian"] == variant and r["jenis"] == jenis]
            print("  {:8s} {:9s}: mean {:.2f}% | stdev {:.2f}% | min {:.2f}% | "
                  "max {:.2f}%".format(variant, jenis, _mean(vals),
                                       _stdev(vals), min(vals), max(vals)))
    print()

    print("[4] Avalanche pesan (CBC, 1000 karakter)")
    message_rows = run_avalanche_message(plaintext_sets, keys)
    _write_dict_csv(os.path.join(OUTPUT_DIR, "aes_avalanche_pesan.csv"),
                    message_rows)
    for variant in aes_cipher.VARIANTS:
        vals = [r["persen_byte_berbeda"] for r in message_rows
                if r["varian"] == variant]
        print("  {:8s}: mean {:.2f}% | min {:.2f}% | max {:.2f}%".format(
            variant, _mean(vals), min(vals), max(vals)))
    print()

    print("[5] Entropi & IC (5000 karakter)")
    stat_rows, ref_entropy = run_statistics(plaintext_sets, keys)
    _write_dict_csv(os.path.join(OUTPUT_DIR, "aes_statistik.csv"), stat_rows)
    print("  acuan entropi acak (os.urandom 5000 byte x{}): {:.4f} bit".format(
        ENTROPY_RANDOM_TRIALS, ref_entropy))
    for r in stat_rows:
        print("  {:8s}: entropi {:.4f} bit | rasio IC {:.4f}".format(
            r["varian"], r["entropi_byte"], r["rasio_IC"]))
    print()

    print("[6] Tabel perbandingan ternormalisasi")
    comparison = build_comparison_table(time_summary, stat_rows, avalanche_rows)
    _write_dict_csv(os.path.join(OUTPUT_DIR,
                                 "tabel_perbandingan_ternormalisasi.csv"),
                    comparison)
    for r in comparison:
        print("  {:26s} enc {:.4f} ms | H_norm {:.4f} | IC_ratio {:.4f} | "
              "av_norm {:.4f} | keyspace {:.1f} bit".format(
                  r["Skenario"], r["Waktu Enkripsi 1000 kar (ms)"],
                  r["Entropi Ternormalisasi"], r["Rasio IC"],
                  r["Avalanche Ternormalisasi"],
                  r["Ruang Kunci Nominal (bit)"]))
    print()

    write_info()
    print("Hasil ditulis ke", OUTPUT_DIR)


if __name__ == "__main__":
    main()
