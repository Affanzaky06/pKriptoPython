def enkripsi_rail_fence(text, key):
    # VALIDASI INPUT, minimal 2 baris (rail) untuk membentuk pola zig-zag.
    if key < 2:
        raise ValueError("Jumlah rail minimal 2.")
    if text == "":
        raise ValueError("Teks tidak boleh kosong.")

    # Menghapus semua spasi dari plaintext sebelum dienkripsi.
    text_bersih = "".join(text.split())
    
    jumlah_karakter = len(text_bersih)

    # Membuat matriks berukuran (key x jumlah_karakter) yang awalnya diisi "."
    matriks = [["." for _ in range(jumlah_karakter)] for _ in range(key)]

    # LOGIKA ZIG-ZAG
    # nomor_rail : rail (baris) yang sedang diisi karakter, mulai dari 0 (paling atas)
    # arah_turun : True jika pergerakan rail sedang menuju ke bawah, false jika sedang menuju ke atas
    nomor_rail = 0
    arah_turun = True

    for i in range(jumlah_karakter):
        # Menempatkan karakter ke posisi rail saat ini, kolom ke-i
        matriks[nomor_rail][i] = text_bersih[i]

        # Jika sudah sampai rail paling atas maka arah dipaksa turun
        if nomor_rail == 0:
            arah_turun = True
        # Jika sudah sampai rail paling bawah maka arah dipaksa naik
        elif nomor_rail == key - 1:
            arah_turun = False

        # Pindah satu rail sesuai arah saat ini(+1 kalau turun, -1 kalau naik)
        nomor_rail += 1 if arah_turun else -1

    # VISUALISASI POLA, menggabungkan isi setiap rail menjadi satu baris teks
    visual_matriks = ""
    for r in range(key):
        visual_matriks += f"Rail {r + 1}: " + " ".join(matriks[r]) + "\n"

    # PEMBACAAN CIPHERTEXT PER RAIL, membaca karakter rail per rail dari atas ke bawah,
    ciphertext = ""
    tabel_rail = []  # menyimpan info tiap rail untuk ditampilkan sebagai tabel

    for r in range(key):
        # Ambil karakter satu per satu dari rail ke-r, kolom demi kolom
        rail_text = ""  # tempat menampung karakter asli dari rail

        for c in range(jumlah_karakter):
            karakter = matriks[r][c]  # ambil isi sel di rail r, kolom c
            if karakter != ".":       # kalau bukan tanda kosong (titik)
                rail_text += karakter # tambahkan ke rail_text
        tabel_rail.append({"Rail": f"Rail {r+1}", "Teks Gabungan": rail_text})
        ciphertext += rail_text

    langkah = [
        {
            "title": "1. Visualisasi Pola Zig-Zag",
            "code": visual_matriks
        },
        {
            "title": "2. Pembacaan Karakter per Rail",
            "table": tabel_rail
        },
        {
            "title": "3. Ciphertext Akhir",
            "code": ciphertext
        }
    ]
    return ciphertext, langkah


def dekripsi_rail_fence(ciphertext, key):
    # VALIDASI INPUT
    if key < 2:
        raise ValueError("Jumlah rail minimal 2.")
    if ciphertext == "":
        raise ValueError("Ciphertext tidak boleh kosong.")

    jumlah_karakter = len(ciphertext)

    # PEMBUATAN MATRIKS KOSONG
    matriks = [["." for _ in range(jumlah_karakter)] for _ in range(key)]

    # MENANDAI POSISI ZIG-ZAG 
    # Sebelum mengisi karakter asli, perlu tahu dulu posisi mana saja yang termasuk dalam pola zig-zag (ditandai dengan "*").
    nomor_rail = 0
    arah_turun = True

    for i in range(jumlah_karakter):
        matriks[nomor_rail][i] = "*"
        if nomor_rail == 0:
            arah_turun = True
        elif nomor_rail == key - 1:
            arah_turun = False
        nomor_rail += 1 if arah_turun else -1

    # MENGISI KARAKTER CIPHERTEXT KE POSISI YANG SUDAH DITANDAI
    # Ciphertext dibaca dari depan, lalu dimasukkan ke posisi "*" secara berurutan per rail (rail 1 penuh dulu, baru rail 2, dst)
    posisi_ciphertext = 0
    for r in range(key):
        for c in range(jumlah_karakter):
            if matriks[r][c] == "*":
                matriks[r][c] = ciphertext[posisi_ciphertext]
                posisi_ciphertext += 1

    # VISUALISASI MATRIKS HASIL 
    visual_matriks = ""
    for r in range(key):
        visual_matriks += f"Rail {r + 1}: " + " ".join(matriks[r]) + "\n"

    # MEMBACA ULANG MATRIKS SECARA ZIG-ZAG
    plaintext = ""
    nomor_rail = 0
    arah_turun = True

    for i in range(jumlah_karakter):
        plaintext += matriks[nomor_rail][i]
        if nomor_rail == 0:
            arah_turun = True
        elif nomor_rail == key - 1:
            arah_turun = False
        nomor_rail += 1 if arah_turun else -1

    langkah = [
        {
            "title": "1. Rekonstruksi Matriks Berdasarkan Panjang Ciphertext",
            "code": visual_matriks
        },
        {
            "title": "2. Plaintext (Dibaca Zig-Zag)",
            "code": plaintext
        }
    ]
    return plaintext, langkah