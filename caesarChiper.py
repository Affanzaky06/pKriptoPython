# CAESAR CHIPER
def caesar_chiper(text, key, decrypt=False):
    # Menghapus semua spasi dari teks input
    text = text.replace(" ", "")
    hasil = ""
    detailProses = []

    # Menentukan arah pergeseran:
    # decrypt=True, pergeseran negatif (mundur), karena proses dekripsi kebalikan dari enkripsi
    # decrypt=False, pergeseran positif (maju), untuk enkripsi biasa
    if decrypt:
        pergeseran = -key
    else:
        pergeseran = key

    # Membatasi nilai pergeseran ke rentang 0-25.
    pergeseran = pergeseran % 26

    for karakter in text:
        if karakter.isalpha() and karakter.isascii():
            if karakter.issupper():
                dasarHuruf = ord("A")
            else:
                dasarHuruf = ord("a")

            # Mengubah huruf jadi posisi angka 0-25 (A/a=0, B/b=1, ..., Z/z=25) dengan cara: kode huruf dikurangi kode huruf dasarnya
            posisiAwal = ord(karakter) - dasarHuruf
            posisiBaru = (posisiAwal + pergeseran) % 26
            hurufHasil = chr(dasarHuruf + posisiBaru)

            if decrypt:
                operasi = "-"
            else:
                operasi = "+"

            rumus = f"({posisiAwal} {operasi} {key % 26}) mod 26 = {posisiBaru}"

            detailProses.append({
                "Karakter": karakter, 
                "Posisi (0-25)": posisiAwal, 
                "Rumus": rumus, 
                "Hasil": hurufHasil
            })
        else:
            hurufHasil = karakter
            detailProses.append({
                "Karakter": karakter, 
                "Posisi (0-25)": "-", 
                "Rumus": "bukan huruf, tidak diubah", "Hasil": hurufHasil
            })
        hasil += hurufHasil
    return hasil, detailProses

def enkripsi_caesar(text, key):
    # Memanggil fungsi utama dengan decrypt=False -> berarti mode enkripsi (geser maju)
    hasil, detail_proses = caesar_chiper(text, key, False)
    langkah = [
        {
            "judul": "1. Rumus Enkripsi",
            "keterangan": f"Setiap huruf digeser maju sebanyak {key} posisi: C = (P + K) mod 26."
        },
        {
            "judul": "2. Proses Setiap Karakter",
            "tabel": detail_proses
        },
        {
            "judul": "3. Ciphertext",
            "hasil": hasil
        }
    ]
    return hasil, langkah

def caesar_decrypt(text, key):
    # Memanggil fungsi utama dengan decrypt=True -> berarti mode dekripsi (geser mundur)
    hasil, detail_proses = caesar_chiper(text, key, True)
    langkah = [
        {
            "judul": "1. Rumus Dekripsi",
            "keterangan": f"Setiap huruf digeser mundur sebanyak {key} posisi: P = (C - K) mod 26."
        },
        {
            "judul": "2. Proses Setiap Karakter",
            "tabel": detail_proses
        },
        {
            "judul": "3. Plaintext",
            "hasil": hasil
        }
    ]
    return hasil, langkah