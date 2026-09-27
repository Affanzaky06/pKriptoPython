# SUPER ENKRIPSI 
# Caesar -> Rail Fence -> Stream Cipher (LFSR) -> Block Cipher Sederhana

from caesarChiper import enkripsi_caesar, dekripsi_caesar
from railfenceChiper import enkripsi_rail_fence, dekripsi_rail_fence
from streamChiperLFSR import stream_encrypt, stream_decrypt
from blockChiper import enkripsi_block, dekripsi_block

# Urutan enkripsi: klasik dulu, baru modern.
# Teks asli -> (Caesar) -> (Rail Fence) -> (Stream LFSR) -> (Block Cipher) -> Ciphertext akhir (hex)

# 4 kunci dipakai TERPISAH, satu untuk tiap algoritma:
# shift = kunci Caesar (angka pergeseran)
# rails = kunci Rail Fence (jumlah rail, minimal 2)
# seed  = kunci Stream Cipher LFSR (4 atau 5 bit, string "0"/"1")
# key   = kunci Block Cipher (teks bebas, akan diperpanjang jadi 8 byte)

def super_encrypt(text, shift, rails, seed, key):
    # Validasi paling awal: teks asli tidak boleh kosong
    if not text:
        raise ValueError("Plaintext tidak boleh kosong.")

    stages = []  
    # menyimpan (label_tahap, input_tahap, output_tahap, rincian_langkah)

    # Tahap 1: Caesar Cipher 
    # Input : teks asli
    # Output: teks yang huruf-hurufnya sudah digeser
    hasil_caesar, langkah_caesar = enkripsi_caesar(text, shift)
    stages.append(("Tahap 1 - Caesar Cipher", text, hasil_caesar, langkah_caesar))

    # Tahap 2: Rail Fence Cipher
    # Input : hasil Caesar (masih berupa huruf)
    # Output: huruf yang sama tapi urutannya diacak pola zig-zag
    hasil_railfence, langkah_railfence = enkripsi_rail_fence(hasil_caesar, rails)
    stages.append(("Tahap 2 - Rail Fence Cipher", hasil_caesar, hasil_railfence, langkah_railfence))

    # Tahap 3: Stream Cipher (LFSR)
    # Input : hasil Rail Fence (teks huruf)
    # Output: MULAI BERUBAH JADI HEX di sini, karena stream_encrypt mengembalikan
    #         hasil dalam bentuk teks hexadecimal (bukan huruf biasa lagi)
    hasil_stream, langkah_stream = stream_encrypt(hasil_railfence, seed)
    stages.append(("Tahap 3 - Stream Cipher (LFSR)", hasil_railfence, hasil_stream, langkah_stream))

    # Tahap 4: Block Cipher Sederhana
    # Input : hex hasil Stream Cipher, DIPERLAKUKAN SEBAGAI TEKS BIASA
    #         (enkripsi_block otomatis meng-encode string apapun jadi UTF-8,
    #         jadi hex string "1A2B3C" tetap valid sebagai input teks)
    # Output: hex lagi, tapi sudah melalui XOR per blok
    hasil_blokChiper, langkah_blokChiper = enkripsi_block(hasil_stream, key)
    stages.append(("Tahap 4 - Block Cipher Sederhana", hasil_stream, hasil_blokChiper, langkah_blokChiper))

    # s4 adalah ciphertext akhir super enkripsi (dalam bentuk hex)
    return hasil_blokChiper, stages

def super_decrypt(hex_text, shift, rails, seed, key):
    # Dekripsi dilakukan dengan urutan TERBALIK dari enkripsi.
    # Enkripsi   : Caesar -> Rail Fence -> Stream -> Block
    # Dekripsi   : Block  -> Stream -> Rail Fence -> Caesar

    stages = []

    # Tahap 1: Dekripsi Block Cipher Sederhana
    # Input : ciphertext akhir (hex)
    # Output: hex hasil Stream Cipher yang asli (sebelum di-block-cipher-kan)
    hasil_block, langkah_block = dekripsi_block(hex_text, key)
    stages.append(("Tahap 1 - Dekripsi Block Cipher Sederhana", hex_text, hasil_block, langkah_block))


    # Tahap 2: Dekripsi Stream Cipher (LFSR)
    # Input : hex hasil tahap 1
    # Output: teks huruf hasil Rail Fence yang asli (sebelum di-XOR LFSR)
    hasil_stream, langkah_stream = stream_decrypt(hasil_block, seed)
    stages.append(("Tahap 2 - Dekripsi Stream Cipher (LFSR)", hasil_block, hasil_stream, langkah_stream))


    # Tahap 3: Dekripsi Rail Fence Cipher
    # Input : teks huruf hasil tahap 2
    # Output: teks huruf hasil Caesar yang asli (sebelum diacak Rail Fence)
    hasil_railfence, langkah_railfence = dekripsi_rail_fence(hasil_stream, rails)
    stages.append(("Tahap 3 - Dekripsi Rail Fence Cipher", hasil_stream, hasil_railfence, langkah_railfence))


    # Tahap 4: Dekripsi Caesar Cipher
    # Input : teks huruf hasil tahap 3
    # Output: TEKS ASLI (plaintext) sebelum dienkripsi sama sekali
    hasil_caesar, langkah_caesar = dekripsi_caesar(hasil_railfence, shift)
    stages.append(("Tahap 4 - Dekripsi Caesar Cipher", hasil_railfence, hasil_caesar, langkah_caesar))

    # s4 adalah plaintext akhir hasil super dekripsi
    return hasil_caesar, stages