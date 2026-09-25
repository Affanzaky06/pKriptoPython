def enkripsi_rail_fence(text, key):
    if key < 2:
        raise ValueError("Jumlah rail minimal 2.")
    if text == "":
        raise ValueError("Teks tidak boleh kosong.")

    text_bersih = "".join(text.split())
    jumlah_karakter = len(text_bersih)
    matriks = [["." for _ in range(jumlah_karakter)] for _ in range(key)]

    nomor_rail = 0
    arah_turun = True

    for i in range(jumlah_karakter):
        matriks[nomor_rail][i] = text_bersih[i]

        if nomor_rail == 0:
            arah_turun = True
        elif nomor_rail == key - 1:
            arah_turun = False

        nomor_rail += 1 if arah_turun else -1

    visual_matriks = ""
    for r in range(key):
        visual_matriks += f"Rail {r + 1}: " + " ".join(matriks[r]) + "\n"

    ciphertext = ""
    tabel_rail = []

    for r in range(key):
        rail_text = "".join([matriks[r][c] for c in range(jumlah_karakter) if matriks[r][c] != "."])
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
    if key < 2:
        raise ValueError("Jumlah rail minimal 2.")
    if ciphertext == "":
        raise ValueError("Ciphertext tidak boleh kosong.")

    jumlah_karakter = len(ciphertext)
    matriks = [["." for _ in range(jumlah_karakter)] for _ in range(key)]

    nomor_rail = 0
    arah_turun = True

    for i in range(jumlah_karakter):
        matriks[nomor_rail][i] = "*"

        if nomor_rail == 0:
            arah_turun = True
        elif nomor_rail == key - 1:
            arah_turun = False

        nomor_rail += 1 if arah_turun else -1

    posisi_ciphertext = 0
    for r in range(key):
        for c in range(jumlah_karakter):
            if matriks[r][c] == "*":
                matriks[r][c] = ciphertext[posisi_ciphertext]
                posisi_ciphertext += 1

    visual_matriks = ""
    for r in range(key):
        visual_matriks += f"Rail {r + 1}: " + " ".join(matriks[r]) + "\n"

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