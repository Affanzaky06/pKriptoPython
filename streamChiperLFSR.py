# STREAM CIPHER DENGAN LFSR 
# Rumus enkripsi : C = P XOR K
# Rumus dekripsi : P = C XOR K 
# Menentukan bit yang digunakan untuk menghitung feedback. 
# Contoh pada materi: LFSR 4-bit menggunakan b1 XOR b4. 

LFSR_TAPS = {
    4: (1, 4),
    5: (1, 3)
}

# 1. MEMERIKSA SEED / KUNCI LFSR 
def periksa_seed(seed): 
    seed = seed.strip() 
    # Seed tidak boleh kosong 
    if seed == "": raise ValueError("Kunci LFSR tidak boleh kosong.") 
    
    # Seed hanya boleh berisi 0 dan 1 
    for karakter in seed: 
        if karakter != "0" and karakter != "1": 
            raise ValueError( "Kunci LFSR hanya boleh berisi angka 0 dan 1." ) 
        
    # Panjang seed harus 4 sampai 5 bit 
    if len(seed) < 4 or len(seed) > 5:
        raise ValueError(
            "Panjang kunci LFSR harus 4 atau 5 bit."
        )
    
    # Seed tidak boleh semuanya 0 
    if "1" not in seed: 
        raise ValueError( "Kunci LFSR tidak boleh semuanya 0." ) 
    return seed 

# 2. MEMBUAT SATU LANGKAH LFSR 
def langkah_lfsr(register, taps): 
    # Bit pertama menjadi bit yang keluar 
    bit_keluar = register[0] 
    
    # Nilai awal feedback 
    bit_feedback = 0 
    
    # Menghitung feedback menggunakan XOR 
    for nomor_bit in taps: 
        posisi = nomor_bit - 1 
        bit_feedback = bit_feedback ^ int(register[posisi])
        
    # Menggeser register ke kiri 
    for posisi in range(len(register) - 1): 
        register[posisi] = register[posisi + 1] 
        
    # Memasukkan feedback ke posisi terakhir 
    register[len(register) - 1] = str(bit_feedback) 
    
    return bit_keluar, bit_feedback
    
    
# 3. MEMBANGKITKAN KEYSTREAM 
def buat_keystream(seed, jumlah_bit): 
    # Mengubah seed menjadi list agar setiap bit dapat digeser 
    register = [] 
    
    for karakter in seed: 
        register.append(karakter) 
    
    # Menentukan aturan feedback berdasarkan panjang seed 
    jumlah_bit_register = len(seed) 
    taps = LFSR_TAPS[jumlah_bit_register] 
    
    keystream = "" 
    
    for i in range(jumlah_bit): 
        bit_keluar, bit_feedback = langkah_lfsr(register, taps) 
        keystream += bit_keluar 
        
    return keystream
    
# 4. MEMBUAT TRACE / RIWAYAT PROSES LFSR 
def buat_trace_lfsr(seed, jumlah_langkah=16): 
    register = [] 
    
    for karakter in seed: 
        register.append(karakter) 
    
    jumlah_bit_register = len(seed) 
    taps = LFSR_TAPS[jumlah_bit_register] 
    
    trace = [] 
    
    for langkah in range(1, jumlah_langkah + 1): 
        # Menyimpan kondisi register sebelum digeser 
        register_sebelum = "" 
        
        for bit in register: 
            register_sebelum += bit 
            
        # Menjalankan satu langkah LFSR 
        bit_keluar, bit_feedback = langkah_lfsr( register, taps ) 
        
        # Menyimpan kondisi register setelah digeser 
        register_sesudah = "" 
        
        for bit in register: 
            register_sesudah += bit 
            
        # Menyimpan semua informasi langkah 
        data_langkah = { 
            "Langkah": langkah, 
            "Register Sebelum": register_sebelum, 
            "Bit Keluar": bit_keluar, 
            "Feedback": bit_feedback, 
            "Register Sesudah": register_sesudah } 
        trace.append(data_langkah) 
        
    return trace 

# 5. MENGUBAH ANGKA MENJADI BINER 8-BIT 
def ubah_ke_biner(angka): return format(angka, "08b") 

# 6. MELAKUKAN XOR PLAINTEXT / CIPHERTEXT DENGAN KEYSTREAM 
def proses_xor(data, seed): 
    # Membuat register awal dari seed 
    register = [] 
    
    for karakter in seed: 
        register.append(karakter) 
    
    jumlah_bit_register = len(seed) 
    taps = LFSR_TAPS[jumlah_bit_register] 
    hasil = [] 
    detail_proses = [] 
    
    # Memproses setiap byte 
    for byte_data in data: 
        keystream = "" 
        # Satu byte terdiri dari 8 bit 
        for i in range(8): 
            bit_keluar, bit_feedback = langkah_lfsr( register, taps ) 
            keystream += bit_keluar 
        
        # Mengubah keystream biner menjadi angka 
        nilai_keystream = int(keystream, 2) 
        
        # XOR data dengan keystream 
        hasil_byte = byte_data ^ nilai_keystream 
        
        # Menyimpan hasil byte 
        hasil.append(hasil_byte) 
        
        # Menampilkan karakter jika merupakan karakter yang bisa dibaca 
        if 32 <= byte_data <= 126: 
            tampilan_byte = chr(byte_data) 
        else: 
            tampilan_byte = f"0x{byte_data:02X}" 
            
        # Menyimpan detail perhitungan 
        detail = { 
            "Byte": tampilan_byte, 
            "Input (bin)": ubah_ke_biner(byte_data), 
            "Keystream (bin)": keystream, 
            "Output (bin)": ubah_ke_biner(hasil_byte), 
            "Output (hex)": f"{hasil_byte:02X}" } 
        detail_proses.append(detail) 
        
    # Mengubah list angka kembali menjadi bytes 
    hasil_bytes = bytes(hasil) 
        
    return hasil_bytes, detail_proses 
    
# 7. INFORMASI KONFIGURASI LFSR 
def informasi_lfsr(seed): 
    jumlah_bit = len(seed) 
    taps = LFSR_TAPS[jumlah_bit] 
    rumus_feedback = "" 
    
    for i in range(len(taps)): 
        if i > 0: 
            rumus_feedback += " XOR " 
        rumus_feedback += f"b{taps[i]}" 

    periode_maksimal = (2 ** jumlah_bit) - 1 
        
    informasi = { 
        "Jumlah Register": jumlah_bit, 
        "Seed": seed, 
        "Rumus Feedback": rumus_feedback, 
        "Periode Maksimal": periode_maksimal } 
    
    return informasi 
    
  # 8. ENKRIPSI STREAM CIPHER 
def stream_encrypt(text, seed): 
    # Memeriksa seed 
    seed = periksa_seed(seed) 
    
    # Mengubah plaintext menjadi byte UTF-8 
    data = text.encode("utf-8") 
    
    if len(data) == 0: 
        raise ValueError("Plaintext tidak boleh kosong.") 
    
    # Mendapatkan informasi LFSR 
    informasi = informasi_lfsr(seed) 
    
    # Membuat trace LFSR 
    trace = buat_trace_lfsr(seed, 16) 
    
    # Melakukan XOR plaintext dengan keystream 
    hasil, detail_proses = proses_xor(data, seed) 
    
    # Mengubah hasil menjadi hexadecimal 
    ciphertext = hasil.hex().upper() 
    langkah = [ 
        { "title": "1. Konfigurasi LFSR", "desc": ( f"Register {informasi['Jumlah Register']} bit, " f"seed = {informasi['Seed']}. " f"Fungsi feedback = {informasi['Rumus Feedback']}. " f"Periode maksimum = {informasi['Periode Maksimal']} bit." ) }, 
        { "title": "2. Trace LFSR", "desc": "Berikut proses 16 langkah pertama pembangkitan keystream.", "table": trace }, 
        { "title": "3. Enkripsi XOR", "desc": "Setiap byte plaintext di-XOR dengan 8 bit keystream.", "table": detail_proses }, 
        { "title": "4. Ciphertext", "code": ciphertext } 
    ] 
    return ciphertext, langkah 

# 9. MENGUBAH HEXADECIMAL MENJADI BYTE - buat dekripsi stream cipher 
def ubah_hex_ke_bytes(hex_text): 
    # Menghapus spasi 
    hex_text = "".join(hex_text.split()) 
    
    # Panjang hexadecimal harus genap 
    if len(hex_text) % 2 != 0: 
        raise ValueError( "Ciphertext hexadecimal harus memiliki jumlah karakter genap." ) 
        
    # Memeriksa setiap karakter hexadecimal 
    karakter_valid = "0123456789ABCDEFabcdef" 
    
    for karakter in hex_text: 
        if karakter not in karakter_valid: 
            raise ValueError( "Ciphertext hanya boleh berisi angka 0-9 dan huruf A-F." ) 
    
    # Mengubah hexadecimal menjadi bytes 
    return bytes.fromhex(hex_text) 

# 10. DEKRIPSI STREAM CIPHER 
def stream_decrypt(hex_text, seed): 
    # Memeriksa seed 
    seed = periksa_seed(seed) 
    
    # Mengubah ciphertext hexadecimal menjadi bytes 
    data = ubah_hex_ke_bytes(hex_text) 
    
    if len(data) == 0: 
        raise ValueError("Ciphertext tidak boleh kosong.") 

    # Mendapatkan informasi LFSR 
    informasi = informasi_lfsr(seed) 
    
    # Membuat trace LFSR 
    trace = buat_trace_lfsr(seed, 16) 
    
    # Melakukan XOR ciphertext dengan keystream 
    hasil, detail_proses = proses_xor(data, seed) 
    
    # Mengubah hasil byte menjadi teks 
    try: 
        plaintext = hasil.decode("utf-8") 
    except UnicodeDecodeError: 
        raise ValueError( "Hasil dekripsi bukan teks UTF-8 yang valid. " "Pastikan kunci LFSR benar." ) 
    
    langkah = [ 
        { "title": "1. Konfigurasi LFSR", "desc": ( f"Register {informasi['Jumlah Register']} bit, " f"seed = {informasi['Seed']}. " f"Fungsi feedback = {informasi['Rumus Feedback']}. " f"Periode maksimum = {informasi['Periode Maksimal']} bit." ) }, 
        { "title": "2. Trace LFSR", "desc": "Keystream yang digunakan harus sama dengan saat enkripsi.", "table": trace }, 
        { "title": "3. Dekripsi XOR", "desc": "Ciphertext di-XOR dengan keystream yang sama untuk mendapatkan plaintext.", "table": detail_proses }, 
        { "title": "4. Plaintext", "code": plaintext } 
    ] 
    return plaintext, langkah