"""Modul definisi algoritma dan skenario perbandingan.

Modul ini memuat:

1. Kunci yang dipakai secara **konsisten** di seluruh skenario (supaya
   perbandingan antar skenario adil).
2. Tujuh (7) skenario algoritma yang dibandingkan, mulai dari algoritma
   tunggal hingga kombinasi tiga algoritma (Multiple Super Encryption).
3. Fungsi uji kebenaran (correctness check) yang memastikan bahwa setiap
   skenario dapat mendekripsi kembali ciphertext menjadi plaintext yang
   **sama persis** sebelum hasilnya dipakai untuk pengujian.

Algoritma dasar (Vigenere, Hill, Transposisi Kolom) diimpor dari modul
``vigenere.py``, ``hill.py``, dan ``transposition.py`` yang sudah ada dan
teruji.  Seluruh skenario bekerja pada alfabet A-Z (26 huruf) karena:

* Analisis frekuensi dilakukan pada huruf A-Z,
* Index of Coincidence dibandingkan terhadap nilai acak ideal 1/26 ~ 0.0385,
* Ruang kunci Vigenere = 26^n dan Hill = jumlah matriks invertible mod 26.

.. note:: **Catatan penting tentang ruang kunci gabungan**

   Ruang kunci gabungan pada skenario kombinasi dihitung sebagai **perkalian**
   ruang kunci tiap lapisan (Vigenere 26^n, Hill |GL(n, Z_26)|, Transposisi
   n!).  Angka ini adalah ukuran teoretis terhadap serangan *brute force naif*
   (mencoba semua kunci satu per satu).  Perkalian ruang kunci **tidak**
   menjamin ketahanan terhadap serangan yang lebih canggih pada skema berlapis,
   misalnya *meet-in-the-middle attack*, karena kompleksitas serangan tersebut
   bisa jauh lebih kecil daripada ukuran ruang kunci gabungan.  Dengan demikian
   klaim keamanan pada Bab III/IV harus disampaikan secara hati-hati dan tidak
   berlebihan.
"""

import random

import vigenere
import hill
import transposition

from alphabet import ALPHABET_26, validate_text

# ---------------------------------------------------------------------------
# Konfigurasi kunci (SAMA untuk semua skenario)
# ---------------------------------------------------------------------------
ALPHABET = ALPHABET_26          # A-Z (26 huruf), modulus m = 26
PAD_CHAR = ALPHABET[0]          # 'A', dipakai untuk padding Hill Cipher

# Kunci Vigenere (dipakai identik pada Vigenere tunggal maupun kombinasi).
VIGENERE_KEY = "KUNCI"

# Kunci Transposisi Kolom (panjang kunci = jumlah kolom = 6, huruf unik
# sehingga ruang kunci teoretisnya tepat n! = 6! = 720).
TRANSPOSITION_KEY = "KRIPTO"

# Kunci Hill Cipher: matriks 3x3 yang invertible modulo 26.
# Determinan = 25 (gcd(25, 26) = 1), sehingga matriks punya invers modulo 26.
HILL_MATRIX = [
    [6, 24, 1],
    [13, 16, 10],
    [20, 17, 15],
]

HILL_BLOCK_SIZE = len(HILL_MATRIX)  # 3

# Lebar header panjang plaintext untuk skenario yang melibatkan Hill Cipher.
#
# Pendekatan yang dipilih: panjang plaintext di-encode dalam **basis 26**
# menggunakan huruf A-Z (A=0 .. Z=25), lalu di-left-pad dengan 'A' selebar
# HEADER_WIDTH.  Alasan pemilihan ini dibandingkan alternatif "padding
# self-describing":
#
# * Header tetap berada sepenuhnya di alfabet A-Z (murni), konsisten dengan
#   seluruh pipa yang bekerja di A-Z.  Skema lama memakai digit 0-9 yang
#   justru melanggar asumsi "alfabet murni".
# * Lebar tetap (fixed-width) membuat dekripsi trivial dan tidak ambigu:
#   cukup baca HEADER_WIDTH karakter pertama lalu decode basis-26.
# * Padding Hill menyebar oleh transposisi, sehingga panjang asli plaintext
#   harus disimpan terpisah; skema PKCS#7-style (padding self-describing)
#   justru tidak cocok karena karakter padding ikut terpermutasi dan nilai
#   paddingnya pun bisa tertukar dengan karakter plaintext 'A'.
#
# HEADER_WIDTH = 5 cukup untuk plaintext hingga 26^5 - 1 = 11.881.375 karakter.
HEADER_WIDTH = 5

# Validasi + inversi matriks Hill dilakukan SEKALI SAJA di sini (saat setup),
# bukan setiap kali encrypt/decrypt dipanggil.  Ini penting supaya pengukuran
# waktu proses mencerminkan waktu enkripsi yang sesungguhnya, bukan overhead
# validasi/inversi matriks yang berkompleksitas O(n!).
HILL_KEY_MATRIX, HILL_KEY_INVERSE = hill.prepare_key(HILL_MATRIX, ALPHABET)


# ---------------------------------------------------------------------------
# Helper: padding Hill dan header panjang
# ---------------------------------------------------------------------------
def _pad_to_block(text):
    """Tambahkan padding 'A' agar panjang teks kelipatan ukuran blok Hill."""
    return text + PAD_CHAR * hill.pad_length(len(text), HILL_BLOCK_SIZE)


def _encode_length(length):
    """Enkode panjang plaintext menjadi header basis-26 selebar HEADER_WIDTH.

    Nilai *length* dikonversi ke basis 26 (A=0, ..., Z=25) lalu di-left-pad
    dengan 'A' (nol).  Hasilnya tetap berada di alfabet A-Z.
    """
    if length >= 26 ** HEADER_WIDTH:
        raise ValueError(
            "panjang plaintext {} melebihi kapasitas header (26^{} - 1)"
            .format(length, HEADER_WIDTH)
        )
    digits = []
    n = length
    for _ in range(HEADER_WIDTH):
        digits.append(ALPHABET[n % 26])
        n //= 26
    return "".join(reversed(digits))


def _decode_length(header):
    """Dekode header basis-26 (selebar HEADER_WIDTH) menjadi integer."""
    value = 0
    for ch in header:
        value = value * 26 + ALPHABET.index(ch)
    return value


def _strip_padding(text, original_length):
    """Buang karakter padding Hill setelah dekripsi."""
    return text[:original_length]


# ---------------------------------------------------------------------------
# Kelas skenario
# ---------------------------------------------------------------------------
class Scenario:
    """Satu skenario algoritma yang dapat dienkripsi/didekripsi.

    Attributes:
        name (str): nama skenario.
        components (list[str]): daftar nama algoritma penyusun (untuk
            perhitungan ruang kunci gabungan).
        header_width (int): lebar header yang ditambahkan pada ciphertext
            (HEADER_WIDTH untuk skenario ber-Hill, 0 untuk lainnya).
        encrypt (callable): ``encrypt(plaintext) -> ciphertext``.
        decrypt (callable): ``decrypt(ciphertext) -> plaintext``.
    """

    def __init__(self, name, components, encrypt, decrypt, header_width=0,
                 vigenere_key=None, hill_matrix=None, hill_inverse=None,
                 transposition_key=None):
        self.name = name
        self.components = components
        self.encrypt = encrypt
        self.decrypt = decrypt
        self.header_width = header_width
        self._vigenere_key = vigenere_key
        self._hill_matrix = hill_matrix
        self._hill_inverse = hill_inverse
        self._transposition_key = transposition_key

    def cipher_body(self, plaintext):
        """Kembalikan *badan* ciphertext (tanpa header panjang).

        Badan inilah yang dipakai untuk menghitung metrik statistik (IC,
        frekuensi, entropi) supaya header tidak mengganggu perhitungan.
        """
        return self.encrypt(plaintext)[self.header_width:]

    def flipped_key_variant(self, position=None):
        """Kembalikan skenario baru dengan SATU karakter kunci diubah.

        Kunci yang diubah adalah kunci pertama yang tersedia: Vigenere,
        Transposisi, atau (untuk Hill) satu entri matriks.  Dipakai untuk
        mengukur *key sensitivity* / key avalanche effect.

        Args:
            position (int | None): indeks karakter kunci string yang diubah,
                atau indeks entri matriks (``row*n + col``) untuk Hill. Bila
                ``None`` dipilih acak.
        """
        if self._vigenere_key is not None:
            return _build_scenario(
                self.name, self.components,
                vigenere_key=_flip_key_string(self._vigenere_key, position),
                hill_matrix=self._hill_matrix, hill_inverse=self._hill_inverse,
                transposition_key=self._transposition_key,
            )
        if self._transposition_key is not None:
            return _build_scenario(
                self.name, self.components,
                vigenere_key=self._vigenere_key,
                hill_matrix=self._hill_matrix, hill_inverse=self._hill_inverse,
                transposition_key=_flip_key_string(self._transposition_key,
                                                   position),
            )
        if self._hill_matrix is not None:
            new_matrix = _flip_hill_matrix(self._hill_matrix, position)
            new_inverse = hill.matrix_inverse(new_matrix, len(ALPHABET))
            return _build_scenario(
                self.name, self.components,
                vigenere_key=self._vigenere_key,
                hill_matrix=new_matrix, hill_inverse=new_inverse,
                transposition_key=self._transposition_key,
            )
        raise ValueError("scenario {} tidak punya kunci yang bisa diubah"
                         .format(self.name))


# ---------------------------------------------------------------------------
# Helper: membangun closure encrypt/decrypt dari daftar komponen
# ---------------------------------------------------------------------------
def _make_scenario_encrypt(components, vigenere_key, hill_matrix,
                           hill_inverse, transposition_key):
    """Bangun pasangan (encrypt, decrypt) untuk kombinasi *components*.

    Urutan pemrosesan mengikuti urutan penyebutan pada flowchart: substitusi
    (Vigenere/Hill) terlebih dahulu, baru transposisi di bagian akhir.  Header
    panjang (bila ada Hill) diletakkan paling depan dan TIDAK ikut ditransposisi.
    """
    has_hill = "Hill" in components

    def encrypt(plaintext):
        result = plaintext
        if "Vigenere" in components:
            result = vigenere.encrypt(result, vigenere_key, ALPHABET)
        if "Hill" in components:
            result = hill.encrypt(_pad_to_block(result), hill_matrix,
                                  ALPHABET, validate=False)
        if "Transposisi" in components:
            result = transposition.encrypt(result, transposition_key)
        if has_hill:
            result = _encode_length(len(plaintext)) + result
        return result

    def decrypt(ciphertext):
        original_length = 0
        body = ciphertext
        if has_hill:
            original_length = _decode_length(ciphertext[:HEADER_WIDTH])
            body = ciphertext[HEADER_WIDTH:]
        result = body
        if "Transposisi" in components:
            result = transposition.decrypt(result, transposition_key)
        if "Hill" in components:
            result = hill.decrypt(result, hill_matrix, ALPHABET,
                                  validate=False, inverse=hill_inverse)
            result = _strip_padding(result, original_length)
        if "Vigenere" in components:
            result = vigenere.decrypt(result, vigenere_key, ALPHABET)
        return result

    return encrypt, decrypt


def _build_scenario(name, components, vigenere_key=None, hill_matrix=None,
                    hill_inverse=None, transposition_key=None):
    """Bangun objek :class:`Scenario` dari komponen dan kunci-kuncinya."""
    encrypt, decrypt = _make_scenario_encrypt(
        components, vigenere_key, hill_matrix, hill_inverse, transposition_key
    )
    header_width = HEADER_WIDTH if "Hill" in components else 0
    return Scenario(name, components, encrypt, decrypt, header_width,
                    vigenere_key=vigenere_key, hill_matrix=hill_matrix,
                    hill_inverse=hill_inverse,
                    transposition_key=transposition_key)


def _flip_key_string(key, position=None):
    """Kembalikan salinan *key* dengan satu karakter (pada *position*) diganti."""
    if position is None:
        position = random.randrange(len(key))
    if not 0 <= position < len(key):
        raise ValueError(
            "posisi kunci {} di luar rentang [0, {})".format(position, len(key))
        )
    chars = list(key)
    original = chars[position]
    replacement = original
    while replacement == original:
        replacement = random.choice(ALPHABET)
    chars[position] = replacement
    return "".join(chars)


def _flip_hill_matrix(matrix, position=None):
    """Kembalikan salinan matriks Hill dengan satu entri diubah (tetap valid)."""
    m = len(ALPHABET)
    n = len(matrix)
    if position is None:
        while True:
            i = random.randrange(n)
            j = random.randrange(n)
            delta = random.randrange(1, m)
            candidate = [row[:] for row in matrix]
            candidate[i][j] = (candidate[i][j] + delta) % m
            if hill.mod_inverse(hill.determinant(candidate, m), m) is not None:
                return candidate
    else:
        i = position // n
        j = position % n
        for delta in range(1, m):
            candidate = [row[:] for row in matrix]
            candidate[i][j] = (candidate[i][j] + delta) % m
            if hill.mod_inverse(hill.determinant(candidate, m), m) is not None:
                return candidate
        raise ValueError(
            "tidak ada perubahan entri [{},{}] yang tetap invertible"
            .format(i, j)
        )


# ---------------------------------------------------------------------------
# Definisi 7 skenario
# ---------------------------------------------------------------------------
def _build_scenarios():
    """Bangun dan kembalikan daftar ketujuh skenario perbandingan."""
    return [
        _build_scenario("1. Vigenere", ["Vigenere"],
                        vigenere_key=VIGENERE_KEY),
        _build_scenario("2. Hill", ["Hill"],
                        hill_matrix=HILL_KEY_MATRIX,
                        hill_inverse=HILL_KEY_INVERSE),
        _build_scenario("3. Transposisi Kolom", ["Transposisi"],
                        transposition_key=TRANSPOSITION_KEY),
        _build_scenario("4. Vigenere + Hill", ["Vigenere", "Hill"],
                        vigenere_key=VIGENERE_KEY,
                        hill_matrix=HILL_KEY_MATRIX,
                        hill_inverse=HILL_KEY_INVERSE),
        _build_scenario("5. Vigenere + Transposisi",
                        ["Vigenere", "Transposisi"],
                        vigenere_key=VIGENERE_KEY,
                        transposition_key=TRANSPOSITION_KEY),
        _build_scenario("6. Hill + Transposisi", ["Hill", "Transposisi"],
                        hill_matrix=HILL_KEY_MATRIX,
                        hill_inverse=HILL_KEY_INVERSE,
                        transposition_key=TRANSPOSITION_KEY),
        _build_scenario("7. Vigenere + Hill + Transposisi",
                        ["Vigenere", "Hill", "Transposisi"],
                        vigenere_key=VIGENERE_KEY,
                        hill_matrix=HILL_KEY_MATRIX,
                        hill_inverse=HILL_KEY_INVERSE,
                        transposition_key=TRANSPOSITION_KEY),
    ]


SCENARIOS = _build_scenarios()


# ---------------------------------------------------------------------------
# Uji kebenaran (correctness check)
# ---------------------------------------------------------------------------
def verify_scenarios(test_texts=None):
    """Uji bahwa setiap skenario mendekripsi ciphertext menjadi plaintext asli.

    Args:
        test_texts (list[str] | None): daftar plaintext uji. Jika ``None``,
            dipakai sekumpulan kasus uji bawaan (termasuk kasus tepi).

    Returns:
        bool: ``True`` jika semua skenario lulus untuk semua plaintext uji.
            Mencetak laporan per skenario. Melempar ``AssertionError`` jika
            ada skenario yang gagal.
    """
    if test_texts is None:
        test_texts = [
            "",                     # kosong
            "A",                    # 1 karakter
            "AB",                   # lebih kecil dari blok Hill (3)
            "ABC",                  # tepat 1 blok Hill
            "ABCD",                 # 1 blok + 1 (butuh padding)
            "SERANG",               # 6 karakter
            "SKRIPSI",              # panjang sama dengan kunci transposisi
            "KRIPTOGRAFI",          # 11 karakter
            "ANALISISKINERJASUPERENKRIPSI",   # campuran panjang
        ]
        # Tambahkan teks acak A-Z dengan berbagai panjang (termasuk kelipatan
        # blok Hill dan non-kelipatan) untuk memastikan padding selalu benar.
        rng = random.Random(12345)
        for _ in range(20):
            length = rng.randint(0, 200)
            test_texts.append("".join(
                rng.choice(ALPHABET) for _ in range(length)
            ))

    all_ok = True
    for scenario in SCENARIOS:
        for text in test_texts:
            validate_text(text, ALPHABET)  # pastikan hanya A-Z
            ciphertext = scenario.encrypt(text)
            recovered = scenario.decrypt(ciphertext)
            if recovered != text:
                all_ok = False
                raise AssertionError(
                    "GAGAL pada skenario {} untuk plaintext {!r}: "
                    "hasil dekripsi {!r}".format(
                        scenario.name, text, recovered
                    )
                )
        print("  [OK] {} lulus uji kebenaran ({} kasus)".format(
            scenario.name, len(test_texts)
        ))
    return all_ok


if __name__ == "__main__":
    print("Menjalankan uji kebenaran seluruh skenario...")
    verify_scenarios()
    print("Semua skenario LULUS.")
