"""Pembungkus (wrapper) AES memakai library ``cryptography``.

Modul ini menyediakan fungsi enkripsi/dekripsi untuk dua varian:

* ``AES-128`` -- kunci 16 byte,
* ``AES-256`` -- kunci 32 byte.

Mode yang dipakai:

* **CBC + padding PKCS#7** untuk pengukuran waktu, entropi, dan IC.  Padding
  dan pembuatan objek cipher terjadi di dalam fungsi yang diukur supaya
  sebanding dengan ``scenario.encrypt()`` di skripsi.
* **ECB, satu blok 16 byte** khusus untuk uji avalanche per blok (mengukur
  sifat difusi cipher blok, bukan rekomendasi pemakaian).

Kunci dan IV dibangkitkan dari :class:`random.Random` dengan seed yang
tercatat (untuk reprodusibilitas eksperimen).  Ini bukan cara membangkitkan
kunci yang aman untuk sistem nyata.
"""

import random

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

VARIANTS = ("AES-128", "AES-256")
KEY_SIZE = {"AES-128": 16, "AES-256": 32}
BLOCK_SIZE = 16
IV_SIZE = 16


def generate_key(variant, rng):
    """Bangkitkan kunci AES (16 atau 32 byte) dari *rng* (harus random.Random)."""
    return bytes(rng.randrange(256) for _ in range(KEY_SIZE[variant]))


def generate_iv(rng):
    """Bangkitkan IV 16 byte dari *rng*."""
    return bytes(rng.randrange(256) for _ in range(IV_SIZE))


def _aes_cipher(key, mode):
    return Cipher(algorithms.AES(key), mode)


def encrypt_cbc(plaintext_bytes, key, iv):
    """Enkripsi CBC + PKCS#7.  Padding + objek cipher + enkripsi dalam satu panggilan."""
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext_bytes) + padder.finalize()
    encryptor = _aes_cipher(key, modes.CBC(iv)).encryptor()
    return encryptor.update(padded) + encryptor.finalize()


def decrypt_cbc(ciphertext_bytes, key, iv):
    """Dekripsi CBC + buang padding PKCS#7."""
    decryptor = _aes_cipher(key, modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext_bytes) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def encrypt_ecb_block(block_bytes, key):
    """Enkripsi satu blok 16 byte dengan mode ECB (khusus uji avalanche)."""
    encryptor = _aes_cipher(key, modes.ECB()).encryptor()
    return encryptor.update(block_bytes) + encryptor.finalize()


def flip_bit(data, bit_position):
    """Kembalikan salinan *data* dengan satu bit pada *bit_position* dibalik."""
    byte_index = bit_position // 8
    bit_offset = bit_position % 8
    value = bytearray(data)
    value[byte_index] ^= 1 << bit_offset
    return bytes(value)


def differing_bits(a, b):
    """Jumlah bit yang berbeda antara dua baris byte dengan panjang sama."""
    total = 0
    for x, y in zip(a, b):
        total += (x ^ y).bit_count()
    return total
