# Modul Uji Serangan (Tahap 3)

Modul ini menguji apakah ketujuh skenario (khususnya kombinasi *super
encryption*) benar-benar tahan terhadap serangan kriptanalisis klasik, bukan
hanya "terlihat acak" menurut IC dan entropi. Ciphertext dibuat dengan kode
skripsi yang **asli** (`algorithms.py`, `hill.py`, `transposition.py`, dst.),
jadi hasil serangan berlaku untuk implementasi yang diuji.

## Cara memasang

Salin `run_attacks.py` dan folder `serangan/` ke folder yang sama dengan
`algorithms.py`:

```
Algo Skripsi Kriptografi/
├── algorithms.py, hill.py, vigenere.py, transposition.py, ...
├── main_comparison.py
├── run_attacks.py          <- baru
└── serangan/               <- baru
    ├── __init__.py
    ├── common.py            utilitas: aljabar mod 26, kunci acak, skenario
    ├── lang_model.py        model bahasa (frekuensi huruf + trigram)
    ├── classical_attacks.py 3A, 3B, 3F (ciphertext-only)
    ├── linear_attacks.py    3C, 3D, 3E (known-plaintext)
    └── README_serangan.md
```

Tidak butuh library tambahan (hanya pustaka standar Python 3).

## Cara menjalankan

```
python run_attacks.py --keys 3        # uji cepat (±1,5 menit)
python run_attacks.py                 # eksperimen penuh: 50 kunci acak (±30-40 menit)
python run_attacks.py --only 3E-VHT   # satu serangan saja
```

Hasil ada di `hasil/serangan/`:

| File | Isi |
|---|---|
| `serangan_<ID>.csv` | Data mentah, satu baris per percobaan (kunci asli, kunci hasil, sukses/gagal, waktu) |
| `ringkasan_serangan.csv` | Tabel ringkasan untuk paper |
| `info_eksperimen.txt` | Tanggal, versi Python, platform, seed, sumber korpus referensi |

## Daftar serangan

| ID | Skenario | Model penyerang | Metode | Parameter yang divariasikan |
|---|---|---|---|---|
| 3A | Vigenère | ciphertext-only | Chi-squared per kolom untuk tiap periode 1–20, pilih hasil dengan skor trigram terbaik (periode terkecil yang mendekati skor terbaik) | panjang ciphertext 50–1000 |
| 3B | Transposisi | ciphertext-only | Brute force 6! = 720 urutan kolom + skor trigram | panjang ciphertext 50–1000 |
| 3C | Hill | known-plaintext | K = Y·P⁻¹ mod 26 dari 3 blok yang P-nya invertibel | panjang known-plaintext 9–60 |
| 3D | Vigenère + Hill | known-plaintext | Model afin y = K·p + b_j (j = t mod L); K dari selisih blok sekelas, lalu b_j; L dicari 1–20 | panjang known-plaintext 15–300 |
| 3E-HT | Hill + Transposisi | known-plaintext | Coba 720 urutan kolom × serangan 3C | panjang pesan 60–1000 |
| 3E-VHT | Vigenère + Hill + Transposisi | known-plaintext | Coba 720 urutan kolom × serangan 3D | panjang pesan 60–1000 |
| 3F | Vigenère + Transposisi | ciphertext-only | Coba 720 urutan kolom, ranking dengan IC per kolom (Friedman), lalu 3A pada 10 kandidat terbaik | panjang ciphertext 200–1000 |

Asumsi (tulis di bagian Metode paper):

* Algoritma dan skema padding diketahui penyerang (prinsip Kerckhoffs).
* Panjang kunci Vigenère **tidak** diketahui (dicari 1–20).
* Jumlah kolom transposisi dianggap diketahui (6). Kalau ingin tanpa asumsi
  ini, jalankan 3B dengan `cols_range=range(2, 9)` (≈46.000 urutan).
* Setiap parameter diuji dengan 50 kunci acak (seed 2026) dan plaintext acak
  dari korpus.

## Definisi keberhasilan

* **Success rate**: plaintext pulih identik (3A, 3B, 3F), atau kunci hasil
  serangan mendekripsi pesan lain (*held-out*, 301 huruf) dengan benar
  (3C–3E).
* **Terbaca ≥95%** (3A, 3B, 3F): kemiripan urutan huruf (difflib) ≥ 0,95.
  Pada 3F kadang terpilih urutan kolom yang merupakan "rotasi" urutan benar;
  plaintext hasilnya tergeser 1–2 huruf tetapi tetap terbaca utuh.
* **Kunci persis**: kunci yang pulih sama dengan kunci asli. Pada 3E selalu
  ditemukan beberapa kunci **ekuivalen** (kolom `n_equivalent_valid`):
  urutan kolom yang berbeda dari kunci asli tetapi, digabung dengan matriks
  Hill yang barisnya dipermutasi, menghasilkan dekripsi yang sama. Ini
  temuan untuk dibahas: ruang kunci efektif lebih kecil dari ruang kunci
  nominal.
* **Kerja efektif (bit)** = log₂(jumlah kandidat yang dicoba). Bandingkan
  dengan **ruang kunci nominal (bit)** dari skripsi (misal 73,6 bit untuk
  V+H+T).

## Korpus referensi (WAJIB dibaca)

Penyerang butuh statistik bahasa Indonesia (frekuensi huruf, trigram). Agar
eksperimen sah, statistik ini harus dari teks yang **berbeda** dengan
plaintext yang diserang.

* Default (fallback): referensi = UU ITE + UU PDP; plaintext serangan hanya
  diambil dari Pancasila, Proklamasi, dan UUD 1945. Tidak tumpang-tindih,
  tetapi korpus referensinya kecil (±10.800 huruf).
* **Disarankan**: buat `serangan/korpus_referensi.txt` berisi ≥50.000 huruf
  teks bahasa Indonesia lain (misalnya beberapa artikel Wikipedia bahasa
  Indonesia; catat judul dan tanggal unduhnya). Bila file ini ada, file
  inilah yang dipakai, dan seluruh korpus skripsi boleh dipakai sebagai
  plaintext serangan.

`info_eksperimen.txt` mencatat sumber mana yang dipakai. Sebutkan di paper.

## Yang harus dilakukan mahasiswa

1. Pahami dan periksa setiap serangan: baca kode, jalankan `--keys 3`,
   cek beberapa baris CSV secara manual (kunci asli vs kunci hasil).
2. Siapkan `korpus_referensi.txt` (lihat di atas).
3. Jalankan eksperimen penuh (50 kunci) di laptop yang sama dengan
   pengukuran waktu skripsi; catat spesifikasinya.
4. Buat tabel utama paper dari `ringkasan_serangan.csv`: ruang kunci nominal
   vs kerja efektif vs waktu serangan, dan grafik success rate vs panjang
   teks untuk 3A, 3C, 3D.
5. Laporkan penyimpangan atau hasil yang aneh ke pembimbing sebelum menulis.
