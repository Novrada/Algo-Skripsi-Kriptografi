"""Serangan ciphertext-only: 3A (Vigenere), 3B (Transposisi), 3F (V + T).

Model penyerang: hanya memegang ciphertext (badan ciphertext, tanpa header)
dan mengetahui algoritmanya (prinsip Kerckhoffs), tetapi TIDAK tahu kunci
maupun panjang kunci Vigenere.  Jumlah kolom transposisi dianggap diketahui
(default 6) kecuali bila ``cols_range`` diberikan.
"""


from serangan.common import all_orders, to_idx, to_str, undo_transposition


# ---------------------------------------------------------------------------
# Friedman: IC rata-rata per kolom untuk periode tertentu
# ---------------------------------------------------------------------------
def column_ic(idx, period):
    total = 0.0
    used = 0
    for c in range(period):
        col = idx[c::period]
        n = len(col)
        if n < 2:
            continue
        counts = [0] * 26
        for x in col:
            counts[x] += 1
        total += sum(k * (k - 1) for k in counts) / (n * (n - 1))
        used += 1
    return total / used if used else 0.0


# ---------------------------------------------------------------------------
# 3A. Vigenere ciphertext-only
# ---------------------------------------------------------------------------
def _best_shifts(idx, period, lm):
    shifts = []
    for c in range(period):
        col = idx[c::period]
        best = None
        for s in range(26):
            counts = [0] * 26
            for x in col:
                counts[(x - s) % 26] += 1
            chi = lm.chi_squared(counts)
            if best is None or chi < best[0]:
                best = (chi, s)
        shifts.append(best[1])
    return shifts


def _vig_decrypt(idx, shifts):
    p = len(shifts)
    return to_str([(x - shifts[i % p]) % 26 for i, x in enumerate(idx)])


PERIOD_TOLERANCE = 0.05  # toleransi skor (log10 per n-gram) untuk memilih
                         # periode yang lebih kecil (mencegah overfitting)


def attack_vigenere(ciphertext, lm, max_period=20):
    """Pulihkan kunci Vigenere tanpa plaintext.

    Untuk tiap periode 1..max_period: kunci per kolom dipilih dengan
    chi-squared terhadap frekuensi huruf referensi, lalu plaintext kandidat
    dinilai dengan model n-gram.  Periode besar cenderung *overfit* pada
    ciphertext pendek (tiap kolom hanya beberapa huruf), maka dipilih periode
    TERKECIL yang skornya berada dalam ``PERIOD_TOLERANCE`` dari skor terbaik.

    Returns:
        dict: key, period, plaintext, score, candidates_tried.
    """
    idx = to_idx(ciphertext)
    max_period = max(1, min(max_period, len(idx) // 4))
    results = []
    for period in range(1, max_period + 1):
        shifts = _best_shifts(idx, period, lm)
        pt = _vig_decrypt(idx, shifts)
        results.append((lm.score(pt), period, shifts, pt))
    best_score = max(r[0] for r in results)
    for sc, period, shifts, pt in results:          # urut periode naik
        if sc >= best_score - PERIOD_TOLERANCE:
            return {"key": to_str(shifts), "period": period, "plaintext": pt,
                    "score": sc,
                    # tiap periode p mengevaluasi p kolom x 26 pergeseran
                    "candidates_tried": 26 * sum(range(1, max_period + 1))}


# ---------------------------------------------------------------------------
# 3B. Transposisi Kolom ciphertext-only (brute force + skor n-gram)
# ---------------------------------------------------------------------------
def attack_transposition(ciphertext, lm, cols_range=(6,)):
    best = None
    tried = 0
    for n_cols in cols_range:
        for order in all_orders(n_cols):
            tried += 1
            pt = undo_transposition(ciphertext, order)
            sc = lm.score(pt)
            if best is None or sc > best[0]:
                best = (sc, order, pt)
    _, order, pt = best
    return {"order": order, "plaintext": pt, "candidates_tried": tried}


# ---------------------------------------------------------------------------
# 3F. Vigenere + Transposisi ciphertext-only (divide and conquer)
# ---------------------------------------------------------------------------
def attack_vigenere_transposition(ciphertext, lm, n_cols=6, max_period=20,
                                  top_k=10):
    """Serang V+T tanpa plaintext.

    Tahap 1: untuk tiap urutan kolom (n_cols!), balik transposisi lalu ukur
    IC per kolom maksimum untuk periode 2..max_period.  Urutan yang benar
    mengembalikan struktur periodik Vigenere sehingga IC-nya tinggi.
    Tahap 2: jalankan serangan Vigenere (3A) pada top_k urutan terbaik dan
    pilih hasil dengan skor n-gram tertinggi.
    """
    ranked = []
    tried = 0
    max_p = max(2, min(max_period, len(ciphertext) // 10))
    for order in all_orders(n_cols):
        tried += 1
        idx = to_idx(undo_transposition(ciphertext, order))
        score = max(column_ic(idx, p) for p in range(2, max_p + 1))
        ranked.append((score, order))
    ranked.sort(reverse=True)

    cands = []
    for _, order in ranked[:top_k]:
        inner = undo_transposition(ciphertext, order)
        res = attack_vigenere(inner, lm, max_period=max_period)
        cands.append((res["score"], res["period"], order, res))
    best_score = max(c[0] for c in cands)
    # pilih periode terkecil di antara kandidat yang skornya mendekati terbaik
    ok = [c for c in cands if c[0] >= best_score - PERIOD_TOLERANCE]
    _, _, order, res = min(ok, key=lambda c: (c[1], -c[0]))
    return {"order": order, "key": res["key"], "period": res["period"],
            "plaintext": res["plaintext"],
            "candidates_tried": tried + top_k * res["candidates_tried"]}
