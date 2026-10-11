# Perbandingan Cipher Klasik dan Kombinasinya (kode skripsi)

Repo ini memuat kode eksperimen dan hasilnya untuk tujuh skenario cipher klasik
(Vigenere, Hill, Transposisi Kolom, dan kombinasinya) beserta pembanding AES
dan uji serangan Tahap 3.

## Perubahan agar sesuai Bab III revisi

Disalin dari `CATATAN_PERUBAHAN.md` pada paket tambalan:

| Perubahan | File | Alasan |
|---|---|---|
| Kandidat Vigenere = 26 x (1+2+...+periode maks) | `serangan/classical_attacks.py` | Kode lama menghitung 26 x periode maks (520), padahal tiap periode p mengevaluasi p kolom x 26 pergeseran (5.460). |
| Huruf pengganti kunci transposisi harus mengubah urutan kolom | `algorithms.py` | Penggantian yang mempertahankan urutan abjad menghasilkan kunci ekuivalen (avalanche kunci 0%). |
| Avalanche memakai seed 2026 (plaintext) dan 2027 (kunci) | `evaluation.py`, `main_comparison.py` | Sebelumnya tanpa seed, hasil berubah setiap run. |
| Interval kepercayaan Wilson 95% pada ringkasan serangan | `run_attacks.py` | Dipakai di Bab III/IV. |
| Serangan tambahan 3B-K (transposisi, jumlah kolom 2-8, 46.232 urutan) | `run_attacks.py` | Menguji asumsi jumlah kolom diketahui. |
| Acuan acak 100 teks A-Z (seed 2026) | `acuan_acak.py` (baru) | Pembanding entropi/IC sampel berhingga. |

Tidak berubah: perilaku serangan dan kunci. Tingkat keberhasilan, "terbaca", dan
kunci persis pada 36 baris ringkasan identik dengan run asli.

### Data waktu proses

Hasil waktu proses (laptop i5-10300H) **tidak diganti**. Pada
`hasil/hasil_perbandingan.csv`, kolom waktu (Waktu Enkripsi/Dekripsi, Stdev,
Throughput) diambil dari run lama; semua kolom lain berasal dari run baru.
File `hasil/waktu_per_ukuran.csv`, `hasil/grafik_waktu_proses.png`, dan
`hasil/grafik_waktu_vs_ukuran.png` tetap versi run lama.

### Tabel normalisasi 5000 huruf

`hasil/aes/tabel_perbandingan_ternormalisasi.csv` yang lama memakai IC dan
entropi pada sampel 1000 huruf, sedangkan Bab III menyebut 5000 huruf. File itu
kini bernama `hasil/aes/tabel_perbandingan_ternormalisasi_1000.csv` (isinya
tidak diubah), dan versi 5000 huruf dibuat oleh `buat_tabel_ternormalisasi.py`
menjadi `hasil/tabel_perbandingan_ternormalisasi_5000.csv`.

Skrip itu hanya membaca CSV yang sudah ada (tidak mengukur ulang apa pun):
entropi/ideal dan rasio IC dari `hasil/frekuensi_karakter.csv` (sampel 5000
huruf), avalanche/ideal dari `hasil/avalanche.csv` dibagi 96,15, waktu enkripsi
1000 huruf dari run lama, dan baris AES dari `hasil/aes/`.
`baseline_aes/run_aes.py` **tidak** dijalankan ulang agar waktu AES tetap.

### Catatan `hasil_perbandingan.xlsx`

Sheet `Avalanche` dan kolom avalanche pada sheet `Ringkasan` sudah diperbarui
dari CSV baru. Sheet lain (termasuk `Waktu per Ukuran`) tetap seperti run lama.

## Cara menjalankan ulang

Butuh Python 3 serta `matplotlib` dan `openpyxl`.

```bash
# 1) metrik utama: waktu, IC, entropi, frekuensi, avalanche, dispersi, ruang kunci
python main_comparison.py

# 2) acuan acak A-Z (IC dan entropi sampel berhingga, seed 2026)
python acuan_acak.py

# 3) uji serangan 3A-3F (50 kunci acak per parameter)
python run_attacks.py

# 4) serangan tambahan 3B-K (jumlah kolom transposisi TIDAK diketahui, 2-8)
python run_attacks.py --only 3B-K --out hasil/serangan_3BK

# 5) tabel normalisasi 5000 huruf (hanya menyusun ulang dari CSV yang ada)
python buat_tabel_ternormalisasi.py
```

Nilai deterministik (avalanche, IC, entropi, tingkat keberhasilan serangan)
harus sama persis seperti yang tersimpan di `hasil/`. Kolom waktu akan berbeda
karena bergantung pada perangkat.

Catatan: `run_attacks.py` tanpa `--only` memakan waktu sekitar 25 menit, dan
`3B-K` sekitar 18 menit (diukur pada Python 3.14.7).

## Analisis tambahan (Langkah 4)

Dua skrip pemeriksaan, keluarannya di `hasil/analisis_tambahan/`. Keduanya hanya
membaca hasil yang sudah ada dan tidak mengubah angka apa pun.

```bash
python analisis_a2_transposisi.py                  # kegagalan serangan 3B
python analisis_avalanche_kunci_transposisi.py     # simpangan baku avalanche kunci
```

* `analisis_a2_transposisi.py` memeriksa 30 percobaan 3B yang `success=False`
  tetapi `readable=True` (panjang 100-1000).
* `analisis_avalanche_kunci_transposisi.py` merinci 10 percobaan avalanche kunci
  (seed 2027) untuk skenario 3 dan 6, dan menyertakan uji kepekaan 200
  percobaan yang **tidak** dipakai di paper.

## Struktur singkat

* `main_comparison.py`, `evaluation.py`, `algorithms.py` - eksperimen utama.
* `vigenere.py`, `hill.py`, `transposition.py`, `alphabet.py` - implementasi cipher.
* `run_attacks.py`, `serangan/` - uji serangan Tahap 3.
* `baseline_aes/` - pembanding AES (tidak dijalankan ulang pada revisi ini).
* `hasil/` - seluruh keluaran yang dipakai paper.
