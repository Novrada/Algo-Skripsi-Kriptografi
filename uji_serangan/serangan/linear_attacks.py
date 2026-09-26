"""Serangan known-plaintext berbasis aljabar linear mod 26: 3C, 3D, 3E.

Dasar teori (urutan lapisan skripsi: Vigenere -> Hill -> Transposisi)::

    Hill saja          : y_t = K p_t                         (mod 26)
    Vigenere + Hill    : y_t = K (p_t + v_j) = K p_t + b_j   (mod 26)

dengan p_t, y_t blok ke-t (3 huruf) dan j = t mod L.  L adalah periode blok
offset: L = k / gcd(k, 3) untuk kunci Vigenere sepanjang k (k = 5 -> L = 5).
Jadi V + H hanyalah cipher AFIN dengan L vektor offset.  Transposisi di
lapisan terakhir hanya menambah pencarian n! urutan kolom (divide and conquer).

Penyerang memegang satu pasangan (plaintext, badan ciphertext).  Hanya blok
PENUH yang dipakai: pada skema skripsi padding 'A' ditambahkan SETELAH
Vigenere, sehingga blok terakhir yang berpadding tidak mengikuti model afin.  Keberhasilan diukur secara FUNGSIONAL: kunci hasil
serangan harus mendekripsi pesan LAIN (held-out) dengan benar.  Kunci yang
berbeda dari kunci asli tetapi lolos uji ini disebut kunci EKUIVALEN.
"""

import itertools
import math

from serangan.common import (all_orders, blocks, inv3, matmul3, matvec3,
                             to_idx, to_str,
                             undo_transposition)

M = 26
REDUNDANCY = 2  # blok ekstra untuk verifikasi


def fit_affine(p_idx, y_idx, period, max_pairs=40):
    """Cari K (dan offset b_j bila period >= 1) yang konsisten.

    Args:
        p_idx, y_idx: indeks plaintext (sudah dipadding) dan output Hill.
        period (int): 0 = Hill murni (tanpa offset); L >= 1 = model afin
            dengan L kelas offset.

    Returns:
        (K, b) atau ``None`` bila model tidak konsisten / data tidak cukup.
    """
    P = blocks(p_idx)
    Y = blocks(y_idx)
    nb = len(P)
    # Jumlah blok harus melebihi jumlah "blok tak diketahui" (3 untuk K,
    # L untuk offset) ditambah REDUNDANCY blok, agar solusi yang lolos
    # verifikasi bukan kebetulan (peluang palsu ~ 26^-(3*REDUNDANCY)).
    if nb < 3 + period + REDUNDANCY:
        return None
    if period == 0:
        pairs = list(zip(P, Y))[:max_pairs]
    else:
        pairs = []
        for j in range(period):
            ts = list(range(j, nb, period))
            for a, b_ in zip(ts, ts[1:]):
                pairs.append(([(P[a][i] - P[b_][i]) % M for i in range(3)],
                              [(Y[a][i] - Y[b_][i]) % M for i in range(3)]))
                if len(pairs) >= max_pairs:
                    break
            if len(pairs) >= max_pairs:
                break
    if len(pairs) < 3:
        return None

    K = None
    for trip in itertools.combinations(range(len(pairs)), 3):
        Pm = [[pairs[k][0][i] for k in trip] for i in range(3)]
        Pinv = inv3(Pm)
        if Pinv is None:
            continue
        Ym = [[pairs[k][1][i] for k in trip] for i in range(3)]
        K = matmul3(Ym, Pinv)
        break
    if K is None:
        return None
    b = []
    if period:
        for j in range(period):
            kp = matvec3(K, P[j])
            b.append([(Y[j][i] - kp[i]) % M for i in range(3)])
    # verifikasi pada SEMUA blok
    for t in range(nb):
        kp = matvec3(K, P[t])
        off = b[t % period] if period else (0, 0, 0)
        for i in range(3):
            if (kp[i] + off[i] - Y[t][i]) % M:
                return None
    if inv3(K) is None:
        return None
    return K, b


def decrypt_with(body, length, K, b, period, order=None):
    """Dekripsi badan ciphertext memakai kunci hasil serangan."""
    y = undo_transposition(body, order) if order is not None else body
    Kinv = inv3(K)
    out = []
    for t, blk in enumerate(blocks(to_idx(y))):
        if period:
            blk = [(blk[i] - b[t % period][i]) % M for i in range(3)]
        out.extend(matvec3(Kinv, blk))
    return to_str(out)[:length]


def recover_vigenere_key(K, b, period, key_len):
    """Rekonstruksi kunci Vigenere (bila panjang kunci diketahui/diduga)."""
    Kinv = inv3(K)
    key = [None] * key_len
    for j in range(period):
        v = matvec3(Kinv, b[j])
        for i in range(3):
            pos = (3 * j + i) % key_len
            if key[pos] is None:
                key[pos] = v[i]
            elif key[pos] != v[i]:
                return None
    if any(k is None for k in key):
        return None
    return to_str(key)


def _search_period(p_idx, y_idx, max_period):
    """Periode offset terkecil (1..max_period) yang konsisten."""
    for L in range(1, max_period + 1):
        r = fit_affine(p_idx, y_idx, L)
        if r:
            return L, r
    return None


# ---------------------------------------------------------------------------
# 3C / 3D: tanpa transposisi
# ---------------------------------------------------------------------------
def attack_hill_kpa(known_pt, known_body):
    """3C. Hill murni, known-plaintext."""
    n3 = len(known_pt) // 3 * 3
    p = to_idx(known_pt[:n3])
    y = to_idx(known_body[:n3])
    r = fit_affine(p, y, 0)
    if not r:
        return None
    return {"K": r[0], "b": r[1], "period": 0, "order": None,
            "candidates_tried": 1}


def attack_vigenere_hill_kpa(known_pt, known_body, max_period=20):
    """3D. Vigenere + Hill, known-plaintext, panjang kunci Vigenere tak diketahui."""
    n3 = len(known_pt) // 3 * 3
    p = to_idx(known_pt[:n3])
    y = to_idx(known_body[:n3])
    found = _search_period(p, y, max_period)
    if not found:
        return None
    L, (K, b) = found
    return {"K": K, "b": b, "period": L, "order": None,
            "candidates_tried": L}


# ---------------------------------------------------------------------------
# 3E: dengan transposisi (divide and conquer atas n! urutan kolom)
# ---------------------------------------------------------------------------
def attack_with_transposition_kpa(known_pt, known_body, with_vigenere,
                                  n_cols=6, max_period=20, full_sweep=True):
    """3E. (Vigenere +) Hill + Transposisi, known-plaintext.

    Untuk tiap urutan kolom: balik transposisi, lalu jalankan 3C/3D.
    Dengan ``full_sweep=True`` seluruh n! urutan dicoba (waktu worst-case)
    dan SEMUA kandidat konsisten dikumpulkan (jumlahnya = banyak kunci
    ekuivalen yang lolos pada data ini).

    Returns:
        dict dengan ``candidates`` (list), ``candidates_tried``,
        ``first_hit_index``.
    """
    n3 = len(known_pt) // 3 * 3
    p = to_idx(known_pt[:n3])
    candidates = []
    tried = 0
    first_hit = None
    for n, order in enumerate(all_orders(n_cols)):
        y = to_idx(undo_transposition(known_body, order)[:n3])
        if with_vigenere:
            found = None
            for L in range(1, max_period + 1):
                tried += 1
                r = fit_affine(p, y, L)
                if r:
                    found = (L, r)
                    break
        else:
            tried += 1
            r = fit_affine(p, y, 0)
            found = (0, r) if r else None
        if found:
            L, (K, b) = found
            candidates.append({"K": K, "b": b, "period": L, "order": order})
            if first_hit is None:
                first_hit = n + 1
            if not full_sweep:
                break
    return {"candidates": candidates, "candidates_tried": tried,
            "first_hit_index": first_hit,
            "work_bits": math.log2(tried) if tried else 0.0}
