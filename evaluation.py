"""Modul evaluasi: metrik pengukuran kinerja dan keamanan cipher.

Menyediakan metode evaluasi yang dipakai untuk membandingkan ketujuh skenario
pada modul :mod:`algorithms`:

1. Waktu proses (enkripsi & dekripsi) dalam milidetik, beserta standar deviasi.
2. Index of Coincidence (IC).
3. Analisis frekuensi karakter A-Z.
4. Entropi Shannon (bit).
5. Analisis ruang kunci + estimasi waktu brute force.
6. Avalanche effect (plaintext sensitivity & key sensitivity).
7. Dispersi posisi (position dispersion).
8. Throughput (karakter per milidetik).

Semua fungsi bersifat independen dari implementasi cipher sehingga bisa dipakai
pada teks apa pun.
"""

import math
import random
import time

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABET_SIZE = len(ALPHABET)          # 26
MAX_ENTROPY = math.log2(ALPHABET_SIZE)  # log2(26) ~ 4.7004 bit
IC_RANDOM = 1.0 / ALPHABET_SIZE         # ~ 0.0385

# Nilai avalanche effect ideal untuk alfabet A-Z: dua string acak independen
# dengan panjang sama akan berbeda di setiap posisi dengan peluang 25/26.
AVALANCHE_IDEAL = 100.0 * (ALPHABET_SIZE - 1) / ALPHABET_SIZE  # ~ 96.15%


# ---------------------------------------------------------------------------
# 1. Waktu proses
# ---------------------------------------------------------------------------
def measure_time(func, *args, repeat=1, warmup=3, **kwargs):
    """Ukur waktu eksekusi ``func(*args, **kwargs)`` dengan statistik lengkap.

    Args:
        func (callable): fungsi yang diukur.
        repeat (int): banyaknya pengulangan yang benar-benar dihitung.
        warmup (int): banyaknya panggilan pemanasan (hasilnya dibuang) untuk
            menghindari bias cold-start / cache.
        *args, **kwargs: argumen yang diteruskan ke *func*.

    Returns:
        dict: ``{"mean_ms": ..., "stdev_ms": ..., "min_ms": ..., "max_ms": ...}``
    """
    if repeat < 1:
        raise ValueError("repeat harus >= 1")

    for _ in range(warmup):
        func(*args, **kwargs)

    samples = []
    for _ in range(repeat):
        start = time.perf_counter()
        func(*args, **kwargs)
        samples.append((time.perf_counter() - start) * 1000.0)

    mean = sum(samples) / len(samples)
    if len(samples) > 1:
        variance = sum((x - mean) ** 2 for x in samples) / (len(samples) - 1)
        stdev = math.sqrt(variance)
    else:
        stdev = 0.0
    return {
        "mean_ms": mean,
        "stdev_ms": stdev,
        "min_ms": min(samples),
        "max_ms": max(samples),
    }


def time_encrypt_decrypt(scenario, plaintext, repeat=1, warmup=3):
    """Ukur waktu enkripsi dan dekripsi suatu skenario.

    Returns:
        dict: ``{"encrypt_ms": ..., "encrypt_stdev_ms": ...,
        "decrypt_ms": ..., "decrypt_stdev_ms": ...}`` dalam milidetik.
    """
    ciphertext = scenario.encrypt(plaintext)  # sekali untuk menyiapkan CT
    enc = measure_time(scenario.encrypt, plaintext, repeat=repeat,
                       warmup=warmup)
    dec = measure_time(scenario.decrypt, ciphertext, repeat=repeat,
                       warmup=warmup)
    return {
        "encrypt_ms": enc["mean_ms"],
        "encrypt_stdev_ms": enc["stdev_ms"],
        "decrypt_ms": dec["mean_ms"],
        "decrypt_stdev_ms": dec["stdev_ms"],
    }


def pooled_stdev(means, stdevs, counts):
    """Gabungkan standar deviasi beberapa kelompok pengukuran.

    Menggunakan rumus variansi gabungan (pooled variance) untuk ``k`` kelompok
    dengan rata-rata ``means[i]``, standar deviasi ``stdevs[i]`` dan jumlah
    sampel ``counts[i]``.

    Returns:
        float: standar deviasi gabungan (0.0 bila total sampel <= 1).
    """
    total = sum(counts)
    if total <= 1:
        return 0.0
    grand_mean = sum(m * c for m, c in zip(means, counts)) / total
    ss = 0.0
    for m, s, c in zip(means, stdevs, counts):
        ss += (c - 1) * (s ** 2) + c * (m - grand_mean) ** 2
    return math.sqrt(ss / (total - 1))


def throughput(characters, time_ms):
    """Hitung throughput dalam karakter per milidetik.

    Args:
        characters (int): panjang plaintext (jumlah karakter yang diproses).
        time_ms (float): waktu enkripsi dalam milidetik.

    Returns:
        float: ``characters / time_ms`` (karakter per milidetik). Mengembalikan
        ``0.0`` bila ``characters == 0`` dan ``float('inf')`` bila ``time_ms``
        nol/non-positif.
    """
    if characters <= 0:
        return 0.0
    if time_ms <= 0:
        return float("inf")
    return characters / time_ms


# ---------------------------------------------------------------------------
# 2. Index of Coincidence (IC)
# ---------------------------------------------------------------------------
def index_of_coincidence(text):
    """Hitung Index of Coincidence (IC) dari *text*.

    IC = sum(n_i * (n_i - 1)) / (N * (N - 1)), dengan n_i frekuensi karakter i
    dan N panjang teks.

    * Teks acak/seragam mendekati ``1/m`` (m = 26 -> ~0.0385).
    * Teks bahasa alami jauh lebih tinggi (Inggris ~0.065).

    Returns:
        float: nilai IC dalam [0, 1] (0.0 untuk teks < 2 karakter).
    """
    n = len(text)
    if n < 2:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    total = sum(c * (c - 1) for c in counts.values())
    return total / (n * (n - 1))


# ---------------------------------------------------------------------------
# 3. Analisis frekuensi karakter
# ---------------------------------------------------------------------------
def frequency_analysis(text):
    """Hitung frekuensi kemunculan setiap huruf A-Z pada *text*.

    Returns:
        dict: pemetaan ``{'A': nA, 'B': nB, ..., 'Z': nZ}`` (urut A-Z).
    """
    counts = {ch: 0 for ch in ALPHABET}
    for ch in text:
        if ch in counts:
            counts[ch] += 1
    return counts


# ---------------------------------------------------------------------------
# 4. Entropi Shannon
# ---------------------------------------------------------------------------
def shannon_entropy(text):
    """Hitung entropi Shannon *text* dalam bit.

    H(X) = -sum(p_i * log2(p_i)), dengan p_i = frekuensi relatif karakter i.

    Returns:
        float: entropi dalam bit (0.0 untuk teks kosong).
    """
    n = len(text)
    if n == 0:
        return 0.0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    entropy = 0.0
    for c in counts.values():
        p = c / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# ---------------------------------------------------------------------------
# 6. Avalanche effect
# ---------------------------------------------------------------------------
def _flip_character(text, position, alphabet=ALPHABET, rng=None):
    """Kembalikan salinan *text* dengan karakter pada *position* diganti lain."""
    rng = rng if rng is not None else random
    chars = list(text)
    original = chars[position]
    replacement = original
    while replacement == original:
        replacement = rng.choice(alphabet)
    chars[position] = replacement
    return "".join(chars)


def _difference_percentage(ciphertext1, ciphertext2):
    """Persentase posisi dengan karakter berbeda antara dua string."""
    length = len(ciphertext1)
    if length == 0:
        return 0.0
    diff = sum(1 for a, b in zip(ciphertext1, ciphertext2) if a != b)
    # Bila panjangnya berbeda (tidak seharusnya untuk skenario yang sama),
    # posisi berlebih ikut dihitung sebagai "berbeda".
    if len(ciphertext2) != length:
        diff += abs(length - len(ciphertext2))
    return 100.0 * diff / max(length, len(ciphertext2))


def avalanche_effect(scenario, plaintext, bit_flip_position=None):
    """Ukur avalanche effect dari *scenario* terhadap perubahan 1 karakter plaintext.

    1. Enkripsi *plaintext* -> ``ciphertext1``.
    2. Ubah SATU karakter plaintext (pada *bit_flip_position*, atau posisi acak
       bila ``None``) -> ``plaintext2``.
    3. Enkripsi ``plaintext2`` -> ``ciphertext2``.
    4. Hitung persentase karakter yang berbeda antara kedua ciphertext.

    Untuk alfabet A-Z, dua ciphertext acak independen idealnya berbeda di
    ``100% * (25/26) ~ 96.15%`` posisi.

    Args:
        scenario: objek dengan metode ``encrypt(plaintext)``.
        plaintext (str): plaintext A-Z (tidak boleh kosong).
        bit_flip_position (int | None): posisi karakter yang diubah. Bila
            ``None`` dipilih acak.

    Returns:
        float: persentase posisi ciphertext yang berbeda (0.0 - 100.0).
    """
    if len(plaintext) == 0:
        raise ValueError("plaintext kosong; avalanche effect butuh minimal 1 karakter")
    n = len(plaintext)
    pos = bit_flip_position if bit_flip_position is not None else random.randrange(n)
    if not 0 <= pos < n:
        raise ValueError(
            "bit_flip_position {} di luar rentang [0, {})".format(pos, n)
        )

    ciphertext1 = scenario.encrypt(plaintext)
    plaintext2 = _flip_character(plaintext, pos)
    ciphertext2 = scenario.encrypt(plaintext2)
    return _difference_percentage(ciphertext1, ciphertext2)


def key_avalanche_effect(scenario, plaintext, key_flip_position=None):
    """Ukur key sensitivity (avalanche effect) terhadap perubahan 1 karakter kunci.

    Mengubah satu karakter dari salah satu kunci *scenario* (Vigenere,
    Transposisi, atau satu entri matriks Hill) lalu membandingkan ciphertext
    yang dihasilkan.

    Args:
        scenario: objek dengan metode ``encrypt`` dan ``flipped_key_variant``.
        plaintext (str): plaintext A-Z (tidak boleh kosong).
        key_flip_position (int | None): indeks karakter kunci yang diubah
            (untuk kunci string); untuk matriks Hill berarti indeks entri
            (row*n + col). Bila ``None`` dipilih acak.

    Returns:
        float: persentase posisi ciphertext yang berbeda (0.0 - 100.0).
    """
    if len(plaintext) == 0:
        raise ValueError("plaintext kosong; key avalanche butuh minimal 1 karakter")
    if not hasattr(scenario, "flipped_key_variant"):
        raise TypeError(
            "scenario harus punya metode flipped_key_variant() untuk key "
            "avalanche effect"
        )

    ciphertext1 = scenario.encrypt(plaintext)
    variant = scenario.flipped_key_variant(position=key_flip_position)
    ciphertext2 = variant.encrypt(plaintext)
    return _difference_percentage(ciphertext1, ciphertext2)


def _mean_stdev(values):
    n = len(values)
    mean = sum(values) / n
    if n > 1:
        variance = sum((v - mean) ** 2 for v in values) / (n - 1)
        return mean, math.sqrt(variance)
    return mean, 0.0


def avalanche_effect_stats(scenario, plaintext, trials=10):
    """Jalankan :func:`avalanche_effect` ``trials`` kali (posisi acak berbeda).

    Returns:
        tuple: ``(mean_percent, stdev_percent)``.
    """
    values = [avalanche_effect(scenario, plaintext) for _ in range(trials)]
    return _mean_stdev(values)


def key_avalanche_effect_stats(scenario, plaintext, trials=10):
    """Jalankan :func:`key_avalanche_effect` ``trials`` kali (posisi acak berbeda).

    Returns:
        tuple: ``(mean_percent, stdev_percent)``.
    """
    values = [key_avalanche_effect(scenario, plaintext) for _ in range(trials)]
    return _mean_stdev(values)


# ---------------------------------------------------------------------------
# 7. Dispersi posisi (position dispersion)
# ---------------------------------------------------------------------------
def changed_positions(ciphertext1, ciphertext2):
    """Kembalikan daftar index tempat karakter dua ciphertext berbeda.

    Perbandingan dilakukan karakter per karakter pada posisi yang sama (zip).
    Panjang kedua ciphertext WAJIB sama; untuk skenario yang sama hal ini selalu
    terpenuhi, tetapi bila tidak maka fungsi melempar :class:`ValueError` supaya
    hasil perbandingan tidak ambigu.

    Args:
        ciphertext1 (str): ciphertext pertama.
        ciphertext2 (str): ciphertext kedua.

    Returns:
        list[int]: index (0-based) posisi-posisi yang karakternya berbeda.
    """
    if len(ciphertext1) != len(ciphertext2):
        raise ValueError(
            "panjang ciphertext tidak sama ({} vs {}); tidak bisa "
            "dibandingkan posisi per posisi".format(
                len(ciphertext1), len(ciphertext2))
        )
    return [i for i, (a, b) in enumerate(zip(ciphertext1, ciphertext2))
            if a != b]


def position_dispersion(positions, text_length):
    """Hitung seberapa menyebar sekumpulan posisi di sepanjang teks.

    Menerapkan dua ukuran sekaligus supaya bisa dibandingkan mana yang lebih
    representatif:

    a) **Standar deviasi posisi** (``stdev``) — stdev sampel (ddof=1) dari
       nilai-nilai index itu sendiri.  Posisi yang mengumpul di satu area
       menghasilkan stdev kecil; posisi yang tersebar merata di seluruh panjang
       teks menghasilkan stdev besar (mendekati stdev distribusi uniform diskrit
       pada [0, text_length-1], yaitu sqrt((L^2 - 1) / 12)).

    b) **Rata-rata jarak antar posisi bertetangga** (``mean_gap``) — posisi
       diurutkan lalu dihitung selisih antara posisi berurutan, kemudian
       dirata-ratakan.  Posisi yang mengumpul punya banyak gap kecil ditambah
       satu gap besar; posisi yang tersebar merata punya gap yang lebih
       konsisten.

    Edge case: bila *positions* kosong atau hanya berisi 1 posisi, tidak ada
    "sebaran" yang dapat dihitung (stdev butuh >= 2 titik, dan gap butuh >= 2
    posisi untuk menghasilkan selisih), sehingga kedua nilai dikembalikan 0.0.

    Args:
        positions (list[int]): index posisi yang berubah (dari
            :func:`changed_positions`).
        text_length (int): panjang teks keseluruhan (dipakai untuk memvalidasi
            rentang index dan sebagai acuan panjang konteks).

    Returns:
        dict: ``{"stdev": ..., "mean_gap": ..., "n_changed": len(positions)}``.
    """
    n = len(positions)
    if positions and (min(positions) < 0 or max(positions) >= text_length):
        raise ValueError(
            "posisi {} di luar rentang [0, {})".format(
                max(positions) if max(positions) >= text_length
                else min(positions), text_length)
        )
    if n < 2:
        return {"stdev": 0.0, "mean_gap": 0.0, "n_changed": n}

    mean = sum(positions) / n
    variance = sum((p - mean) ** 2 for p in positions) / (n - 1)
    stdev = math.sqrt(variance)

    ordered = sorted(positions)
    gaps = [b - a for a, b in zip(ordered, ordered[1:])]
    mean_gap = sum(gaps) / len(gaps)

    return {"stdev": stdev, "mean_gap": mean_gap, "n_changed": n}


def dispersion_effect(scenario, plaintext, bit_flip_position=None, rng=None):
    """Ukur dispersi posisi perubahan ciphertext akibat 1 karakter plaintext.

    Alur sama dengan :func:`avalanche_effect`:

    1. Enkripsi *plaintext* -> ``ciphertext1``.
    2. Ubah SATU karakter plaintext -> ``plaintext2``.
    3. Enkripsi ``plaintext2`` -> ``ciphertext2``.
    4. Hitung posisi yang berubah lalu ukur dispersinya.

    Args:
        scenario: objek dengan metode ``encrypt(plaintext)``.
        plaintext (str): plaintext A-Z (tidak boleh kosong).
        bit_flip_position (int | None): posisi karakter yang diubah. Bila
            ``None`` dipilih acak.
        rng: generator angka acak (mis. :class:`random.Random`) untuk pemilihan
            posisi dan karakter pengganti; dipakai supaya hasil dapat
            direproduksi.

    Returns:
        dict: ``{"changed_position": ..., "text_length": ...,
        "ciphertext_length": ..., "n_changed": ..., "stdev": ...,
        "mean_gap": ...}``.
    """
    if len(plaintext) == 0:
        raise ValueError(
            "plaintext kosong; dispersi posisi butuh minimal 1 karakter"
        )
    rng = rng if rng is not None else random
    n = len(plaintext)
    pos = bit_flip_position if bit_flip_position is not None else rng.randrange(n)
    if not 0 <= pos < n:
        raise ValueError(
            "bit_flip_position {} di luar rentang [0, {})".format(pos, n)
        )

    ciphertext1 = scenario.encrypt(plaintext)
    plaintext2 = _flip_character(plaintext, pos, rng=rng)
    ciphertext2 = scenario.encrypt(plaintext2)

    positions = changed_positions(ciphertext1, ciphertext2)
    dispersion = position_dispersion(positions, len(ciphertext1))
    return {
        "changed_position": pos,
        "text_length": n,
        "ciphertext_length": len(ciphertext1),
        "n_changed": dispersion["n_changed"],
        "stdev": dispersion["stdev"],
        "mean_gap": dispersion["mean_gap"],
    }


def dispersion_effect_stats(scenario, plaintext, trials=10, seed=None):
    """Jalankan :func:`dispersion_effect` ``trials`` kali dengan posisi acak berbeda.

    Args:
        scenario: objek dengan metode ``encrypt``.
        plaintext (str): plaintext A-Z.
        trials (int): banyaknya posisi flip acak (>= 10 disarankan).
        seed (int | None): seed untuk reproducibility. Bila ``None`` dipakai
            generator acak global (hasil tidak deterministik).

    Returns:
        dict: ``{"stdev_mean": ..., "stdev_stdev": ..., "mean_gap_mean": ...,
        "mean_gap_stdev": ..., "trials": trials}``.
    """
    rng = random.Random(seed) if seed is not None else random
    stdev_values = []
    gap_values = []
    for _ in range(trials):
        result = dispersion_effect(scenario, plaintext, rng=rng)
        stdev_values.append(result["stdev"])
        gap_values.append(result["mean_gap"])

    stdev_mean, stdev_std = _mean_stdev(stdev_values)
    gap_mean, gap_std = _mean_stdev(gap_values)
    return {
        "stdev_mean": stdev_mean,
        "stdev_stdev": stdev_std,
        "mean_gap_mean": gap_mean,
        "mean_gap_stdev": gap_std,
        "trials": trials,
    }


# ---------------------------------------------------------------------------
# 5. Analisis ruang kunci
# ---------------------------------------------------------------------------
def key_space_vigenere(key_length):
    """Ruang kunci Vigenere: 26^n (n = panjang kunci)."""
    return ALPHABET_SIZE ** key_length


def key_space_transposition(key_length):
    """Ruang kunci Transposisi Kolom: n! (n = panjang kunci / jumlah kolom)."""
    return math.factorial(key_length)


def _factor(x):
    """Faktorisasi prima *x* -> dict {prima: pangkat}."""
    factors = {}
    d = 2
    while d * d <= x:
        while x % d == 0:
            factors[d] = factors.get(d, 0) + 1
            x //= d
        d += 1
    if x > 1:
        factors[x] = factors.get(x, 0) + 1
    return factors


def _gl_order(n, p, e):
    """|GL(n, Z_{p^e})| = jumlah matriks n×n invertible modulo p^e.

    |GL(n, Z_{p^e})| = p^((e-1)·n²) · prod_{k=0}^{n-1} (p^n - p^k).
    """
    total = p ** ((e - 1) * n * n)
    for k in range(n):
        total *= (p ** n - p ** k)
    return total


def key_space_hill(matrix_size, modulus=ALPHABET_SIZE):
    """Jumlah matriks n×n yang invertible modulo *modulus*.

    Memanfaatkan teorema sisa Cina: untuk modulus komposit ``m = prod p^e``,
    ``|GL(n, Z_m)| = prod |GL(n, Z_{p^e})|``.

    Args:
        matrix_size (int): ukuran matriks n.
        modulus (int): modulus (default 26).

    Returns:
        int: banyaknya matriks kunci Hill yang valid.
    """
    total = 1
    for p, e in _factor(modulus).items():
        total *= _gl_order(matrix_size, p, e)
    return total


def scenario_key_space(scenario, vigenere_key_length, transposition_key_length,
                       hill_matrix_size):
    """Hitung ruang kunci gabungan sebuah skenario.

    Untuk skenario kombinasi, ruang kunci gabungan = **perkalian** ruang kunci
    tiap algoritma penyusunnya.

    Returns:
        dict: pemetaan nama algoritma -> (nama, ruang kunci), plus kunci
        ``"total"`` berisi hasil perkaliannya.
    """
    parts = {}
    if "Vigenere" in scenario.components:
        parts["Vigenere"] = key_space_vigenere(vigenere_key_length)
    if "Hill" in scenario.components:
        parts["Hill"] = key_space_hill(hill_matrix_size)
    if "Transposisi" in scenario.components:
        parts["Transposisi"] = key_space_transposition(
            transposition_key_length
        )

    total = 1
    for value in parts.values():
        total *= value
    parts["total"] = total
    return parts


def format_key_space(value):
    """Format bilangan besar menjadi notasi ilmiah yang mudah dibaca."""
    if value == 0:
        return "0"
    exponent = int(math.floor(math.log10(value)))
    mantissa = value / (10 ** exponent)
    return "{:.2f} x 10^{} (~2^{:.1f} bit)".format(
        mantissa, exponent, math.log2(value)
    )


# ---------------------------------------------------------------------------
# Estimasi waktu brute force
# ---------------------------------------------------------------------------
def brute_force_time(key_space, tries_per_second=1e9):
    """Estimasi lama brute force untuk ruang kunci tertentu.

    Args:
        key_space (int): ukuran ruang kunci.
        tries_per_second (float): asumsi jumlah percobaan kunci per detik
            (default 10^9 percobaan/detik).

    Returns:
        dict: ``{"seconds": ..., "human": ...}`` dengan ``human`` berupa
        string estimasi waktu yang mudah dibaca manusia.
    """
    seconds = key_space / tries_per_second
    return {"seconds": seconds, "human": humanize_seconds(seconds)}


def humanize_seconds(seconds):
    """Ubah durasi (detik) menjadi string yang mudah dibaca manusia."""
    if seconds < 1e-3:
        return "{:.3f} mikrodetik".format(seconds * 1e6)
    if seconds < 1:
        return "{:.3f} milidetik".format(seconds * 1e3)
    if seconds < 60:
        return "{:.3f} detik".format(seconds)

    minute = 60
    hour = 60 * minute
    day = 24 * hour
    year = 365.25 * day

    if seconds < hour:
        return "{:.2f} menit".format(seconds / minute)
    if seconds < day:
        return "{:.2f} jam".format(seconds / hour)
    if seconds < year:
        return "{:.2f} hari".format(seconds / day)
    if seconds < 1e3 * year:
        return "{:.2f} tahun".format(seconds / year)
    return "{:.2e} tahun".format(seconds / year)
