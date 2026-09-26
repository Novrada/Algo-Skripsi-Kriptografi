# Modul 1 — Baseline AES

Titik acuan modern untuk paper perbandingan cipher klasik (Multiple Super
Encryption) — ICIMCIS 2026.  AES **tidak diserang**; AES hanya diukur dengan
metrik yang sama (sejauh bisa dibandingkan) lalu dimasukkan sebagai dua baris
tambahan (AES-128 dan AES-256) pada tabel utama paper.

Modul ini berdiri sendiri: tidak mengubah kode skripsi, hanya memakai
`sample_data.py` untuk plaintext yang sama.

## Struktur

```
baseline_aes/
├── aes_cipher.py     # fungsi enkripsi/dekripsi AES (bungkus library)
├── aes_metrics.py    # avalanche bit, entropi byte, IC byte (+ normalisasi)
├── run_aes.py        # program utama, menulis semua CSV
└── README.md
```

Keluaran ditulis ke `hasil/aes/`.

## Menjalankan

Dari folder induk proyek (yang berisi `algorithms.py`):

```
python baseline_aes/run_aes.py
```

Program akan: (1) uji kebenaran `decrypt(encrypt(x)) == x`, (2) mengukur waktu,
(3) avalanche bit, (4) avalanche pesan, (5) entropi & IC, (6) menulis tabel
perbandingan ternormalisasi, dan (7) menulis `info_lingkungan.txt`.

Estimasi lama: pengukuran waktu mendominasi (±1–2 menit per varian karena
AES memakai C/OpenSSL yang sangat cepat, dengan 2 varian × 5 ukuran × 3 sampel
× hingga 100 repetisi). Total keseluruhan < 5 menit.

## Konfigurasi AES

| Item | Nilai |
|---|---|
| Library utama | `cryptography` |
| Varian | AES-128 dan AES-256 |
| Mode (waktu, entropi, IC) | CBC + padding PKCS#7, IV 16 byte |
| Mode (uji avalanche per blok) | ECB, satu blok 16 byte |
| Plaintext | `sample_data.build_sample_sets([50, 100, 500, 1000, 5000], 3)` |
| Encoding | A–Z di-encode ASCII (1 huruf = 1 byte) |
| Kunci & IV | dari `random.Random(seed)` dengan seed tercatat (2026) |

Kunci dan IV dibangkitkan dari seed semata-mata demi reprodusibilitas
eksperimen; ini **bukan** cara membangkitkan kunci yang aman untuk sistem
nyata (sebutkan ini di paper).

## Metrik

* **Waktu**: 3 sampel per ukuran, warm-up, 100 repetisi (30 untuk 5000
  karakter), `time.perf_counter()`, gc dimatikan selama pengukuran, dan semua
  nilai repetisi mentah disimpan ke `aes_waktu_mentah.csv` (dipakai Modul 2).
* **Avalanche bit**: 1.000 percobaan per varian (50 kunci × 20 posisi bit),
  ideal 50%.  Dilaporkan mean/stdev/min/maks.
* **Avalanche pesan**: 1.000 karakter mode CBC, ubah 1 karakter pada posisi
  acak, 100 percobaan.
* **Entropi byte**: pada ciphertext 5.000 karakter, dibandingkan terhadap
  acuan acak (rata-rata entropi 100 × 5.000 byte `os.urandom`), **bukan**
  terhadap 8,0 (bias sampel terbatas).
* **IC byte**: atas 256 simbol, nilai acak ideal 1/256.

## Normalisasi (bagian 5 dokumen)

| Metrik | Cipher klasik | AES | Nilai ideal |
|---|---|---|---|
| Entropi ternormalisasi | H / log₂26 | H / 8 | mendekati acuan acak |
| Rasio IC | IC × 26 | IC × 256 | 1,0 |
| Avalanche ternormalisasi | avalanche karakter / 96,15% | avalanche bit / 50% | 1,0 |
| Ruang kunci | bit nominal (dan kerja efektif dari uji serangan) | 128 / 256 bit | — |

## File keluaran (`hasil/aes/`)

| File | Isi (kolom utama) |
|---|---|
| `aes_waktu_mentah.csv` | varian, ukuran, sampel_ke, repetisi_ke, operasi (enc/dec), waktu_ms |
| `aes_waktu_ringkasan.csv` | varian, ukuran, operasi, mean, stdev, median, IQR, throughput |
| `aes_avalanche_bit.csv` | varian, jenis (plaintext/kunci), percobaan_ke, bit_berbeda, persen |
| `aes_avalanche_pesan.csv` | varian, percobaan_ke, posisi_diubah, persen_byte_berbeda |
| `aes_statistik.csv` | varian, entropi_byte, acuan_entropi_acak, IC_byte, rasio_IC |
| `tabel_perbandingan_ternormalisasi.csv` | 7 skenario klasik + AES-128 + AES-256 |
| `info_lingkungan.txt` | tanggal, versi Python, versi cryptography, OS, CPU, seed |

## Versi library saat dijalankan

* Python: 3.14.7
* cryptography: 50.0.1

## Catatan penting untuk paper (C vs Python)

`cryptography` memanggil implementasi C (OpenSSL, sering dengan akselerasi
AES-NI), sedangkan cipher klasik skripsi ditulis dalam Python murni.
**Perbandingan waktu tidak setara.**  Kalimat keterbatasan ini harus
dicantumkan di paper (kecuali bila sub-eksperimen `pyaes` dijalankan untuk
pembanding yang setara bahasa).

## Checklist verifikasi (bagian 7 dokumen)

* [x] `decrypt(encrypt(x)) == x` untuk semua sampel dan kedua varian.
* [ ] Avalanche bit plaintext dan kunci AES ~ 50% (±1–2%).
* [ ] Entropi byte AES mendekati acuan acak `os.urandom` (bukan 8,0).
* [ ] Rasio IC AES mendekati 1,0.
* [ ] Waktu diukur di laptop yang sama dengan skripsi; spesifikasi tercatat.
* [ ] Data waktu mentah tersimpan (dibutuhkan Modul 2).
* [ ] Seed tercatat; menjalankan ulang menghasilkan angka avalanche & statistik
      yang sama (acuan os.urandom sedikit bervariasi antar-jalan, itu wajar).
* [x] Catatan "C vs Python" tertulis di atas dan akan dimasukkan ke paper.

Item checklist yang masih kosong (`[ ]`) diverifikasi otomatis oleh
`run_aes.py`; cek keluaran di konsol sebelum diserahkan.
