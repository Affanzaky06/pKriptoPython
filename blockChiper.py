# BLOCK CIPHER (XOR per blok)
# Rumus enkripsi : C = P XOR K
# Rumus dekripsi : P = C XOR K

# ukuran satu blok dalam byte (8 byte = 64 bit)
BLOCK_SIZE = 8

# 1. MENYIAPKAN KUNCI SEPANJANG SATU BLOK
def perpanjang_kunci(key, panjang_blok=BLOCK_SIZE):
    # Validasi kunci tidak boleh kosong
    if not key:
        raise ValueError("Kunci tidak boleh kosong.")

    # Mengubah kunci (teks) jadi bytes, karena XOR cuma bisa dilakukan ke angka/bytes
    kunci_bytes = key.encode("utf-8")

    # Mengulang kunci karakter demi karakter sampai panjangnya PAS SEPANJANG SATU BLOK
    kunci_blok = bytes(kunci_bytes[i % len(kunci_bytes)] for i in range(panjang_blok))
    return kunci_blok

# 2. MENAMBAHKAN PADDING (supaya panjang data pas kelipatan BLOCK_SIZE)
def tambah_padding(data, panjang_blok=BLOCK_SIZE):
    # Block cipher memproses blok yang penuh (utuh sepanjang BLOCK_SIZE).
    # Kalau panjang data tidak pas kelipatan BLOCK_SIZE, tambahkan byte tambahan (padding) di akhir supaya pas.

    # Menghitung berapa byte kurangnya supaya jadi kelipatan panjang_blok
    jumlah_kurang = panjang_blok - (len(data) % panjang_blok)

    # Kalau pas sudah kelipatan, tetap tambahkan satu blok padding penuh agar selalu tahu ada padding yang perlu dibuang (lihat fungsi buang_padding)
    if jumlah_kurang == 0:
        jumlah_kurang = panjang_blok

    # Isi padding: setiap byte tambahan diisi ANGKA jumlah_kurang
    # proses buang_padding: tinggal baca byte terakhir, itulah jumlah byte padding yang harus dibuang.
    return data + bytes([jumlah_kurang] * jumlah_kurang)


# 3. MEMBUANG PADDING
def buang_padding(data, panjang_blok=BLOCK_SIZE):
    if not data:
        return data

    # Byte terakhir menyimpan informasi "berapa banyak padding yang ditambahkan"
    jumlah_padding = data[-1]

    # Validasi: kalau nilainya aneh anggap saja tidak ada padding yang perlu dibuang
    if jumlah_padding < 1 or jumlah_padding > panjang_blok:
        return data

    # Membuang byte padding dari akhir data
    return data[:-jumlah_padding]


# 4. MENG-XOR SATU BLOK DENGAN KUNC
def xor_satu_blok(blok, kunci_blok):
    # zip(blok, kunci_blok) memasangkan byte-byte dari plaintexT dengan bytes kunci.
    hasil = bytes(b_data ^ b_key for b_data, b_key in zip(blok, kunci_blok))

    # Menyimpan rincian tiap byte dalam blok ini
    detail = []
    for i, (b_data, b_key, b_hasil) in enumerate(zip(blok, kunci_blok, hasil), start=1):
        detail.append({
            "Byte ke-": i,
            "Plaintext/Cipher (masuk)": chr(b_data) if 32 <= b_data <= 126 else f"0x{b_data:02X}",
            "Kunci": chr(b_key) if 32 <= b_key <= 126 else f"0x{b_key:02X}",
            "Hasil (hex)": f"{b_hasil:02X}",
        })
    return hasil, detail


# 5. MEMPROSES SELURUH DATA
def proses_per_blok(data, key):
    # Menyiapkan kunci SEKALI SAJA, sepanjang satu blok
    kunci_blok = perpanjang_kunci(key, BLOCK_SIZE)

    hasil_total = bytearray()
    rincian_blok = []

    # Menyusuri data per BLOCK_SIZE byte sekaligus (blok demi blok)
    # range(0, len(data), BLOCK_SIZE) menghasilkan: 0, 8, 16, 24, ...
    # artinya "melompat" sejauh satu blok di setiap perulangan
    for nomor_blok, awal in enumerate(range(0, len(data), BLOCK_SIZE), start=1):
        blok = data[awal:awal + BLOCK_SIZE]

        # kunci_blok yang dipakai di sini SAMA PERSIS untuk setiap blok
        hasil_blok, detail_byte = xor_satu_blok(blok, kunci_blok)

        hasil_total.extend(hasil_blok)
        rincian_blok.append({
            "Blok ke-": nomor_blok,
            "Kunci blok yang dipakai": kunci_blok.hex().upper(),
            "detail": detail_byte,
        })
    return bytes(hasil_total), rincian_blok, kunci_blok

# Fungsi Tambahan untuk tampilan Streamlit
def ratakan_rincian_blok(rincian_blok):
    # Menggabungkan info blok + info tiap byte jadi SATU baris per byte, supaya bisa ditampilkan sebagai tabel datar
    baris_rata = []
    for blok in rincian_blok:
        for baris_byte in blok["detail"]:
            baris_rata.append({
                "Blok ke-": blok["Blok ke-"],
                "Kunci Blok": blok["Kunci blok yang dipakai"],
                **baris_byte
                # membongkar isi baris_byte jadi kolom-kolom baru
            })
    return baris_rata

# 6. ENKRIPSI
def enkripsi_block(text, key):
    # Validasi input
    if text == "":
        raise ValueError("Plaintext tidak boleh kosong.")

    text = text.replace(" ", "")

    # Mengubah teks jadi bytes (format UTF-8)
    data = text.encode("utf-8")

    # Menambahkan padding supaya panjangnya pas kelipatan BLOCK_SIZE
    data_padded = tambah_padding(data, BLOCK_SIZE)

    # Memproses seluruh data, blok demi blok, XOR dengan kunci yang sama tiap blok
    hasil_bytes, rincian_blok, kunci_blok = proses_per_blok(data_padded, key)

    # Mengubah hasil (bytes) jadi teks hexadecimal biar gampang ditampilkan/disimpan
    ciphertext = hasil_bytes.hex().upper()

    langkah = [
        {
            "title": "1. Padding & Pembagian Blok",
            "desc": (f"Plaintext ({len(data)} byte) di-padding jadi {len(data_padded)} byte, "
                     f"lalu dibagi menjadi {len(rincian_blok)} blok berukuran {BLOCK_SIZE} byte.")
        },
        {
            "title": "2. Kunci per Blok",
            "desc": (f"Kunci '{key}' diperpanjang jadi {BLOCK_SIZE} byte: {kunci_blok.hex().upper()}. "
                     f"Kunci ini dipakai SAMA PERSIS untuk semua blok (tidak berubah antar blok).")
        },
        {
            "title": "3. XOR per Blok (C = P XOR K)",
            "table": ratakan_rincian_blok(rincian_blok)
        },
        {
            "title": "4. Ciphertext (Hex)",
            "code": ciphertext
        }
    ]
    return ciphertext, langkah


# 7. MENGUBAH TEKS HEXADECIMAL KEMBALI JADI BYTES
def hex_ke_bytes(hex_text):
    # Menghapus spasi kalau ada
    hex_text = "".join(hex_text.split())

    # Hex harus punya jumlah karakter genap (2 karakter hex = 1 byte)
    if len(hex_text) % 2 != 0:
        raise ValueError("Ciphertext hexadecimal harus memiliki jumlah karakter genap.")

    # Memastikan semua karakternya valid karakter hex (0-9, A-F, a-f)
    karakter_valid = "0123456789ABCDEFabcdef"
    for karakter in hex_text:
        if karakter not in karakter_valid:
            raise ValueError("Ciphertext hanya boleh berisi angka 0-9 dan huruf A-F.")
    return bytes.fromhex(hex_text)

# 8. DEKRIPSI
def dekripsi_block(ciphertext_hex, key):
    # Validasi input
    if ciphertext_hex == "":
        raise ValueError("Ciphertext tidak boleh kosong.")

    # Mengubah ciphertext (hex) jadi bytes
    data = hex_ke_bytes(ciphertext_hex)

    # Memproses seluruh data, blok demi blok. Karena XOR dua kali dengan
    # kunci yang sama akan mengembalikan data asli (P = C XOR K), fungsi
    # yang dipakai SAMA PERSIS dengan proses enkripsi
    hasil_bytes, rincian_blok, kunci_blok = proses_per_blok(data, key)

    # Membuang padding yang ditambahkan saat enkripsi
    hasil_tanpa_padding = buang_padding(hasil_bytes, BLOCK_SIZE)

    # Mengubah bytes hasil dekripsi kembali jadi teks biasa
    try:
        plaintext = hasil_tanpa_padding.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Hasil dekripsi bukan teks UTF-8 yang valid. Kunci kemungkinan salah.")

    langkah = [
        {
            "title": "1. Kunci per Blok",
            "desc": (f"Kunci '{key}' diperpanjang jadi {BLOCK_SIZE} byte: {kunci_blok.hex().upper()}. "
                     f"Kunci yang sama ini dipakai untuk membalikkan (dekripsi) semua blok.")
        },
        {
            "title": "2. XOR per Blok (P = C XOR K)",
            "desc": "Operasi sama persis seperti enkripsi, karena (P XOR K) XOR K = P.",
            "table": ratakan_rincian_blok(rincian_blok)
        },
        {
            "title": "3. Buang Padding & Plaintext Asli",
            "code": plaintext
        }
    ]
    return plaintext, langkah