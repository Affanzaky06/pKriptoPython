def caesar_chiper(text, key, decrypt=False):
    # Hilangkan spasi dari teks input
    text = text.replace(" ", "")
    hasil = ""
    detailProses = []
    pergeseran = -key if decrypt else key
    pergeseran = pergeseran % 26

    for karakter in text:
        if karakter.isalpha() and karakter.isascii():
            dasarHuruf = ord("A") if karakter.isupper() else ord("a")
            posisiAwal = ord(karakter) - dasarHuruf
            posisiBaru = (posisiAwal + pergeseran) % 26
            hurufHasil = chr(dasarHuruf + posisiBaru)

            operasi = "-" if decrypt else "+"
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
                "Rumus": "bukan huruf, tidak diubah",
                "Hasil": hurufHasil
            })
        hasil += hurufHasil
    return hasil, detailProses

def enkripsi_caesar(text, key):
    hasil, detail_proses = caesar_chiper(text, key, False)
    langkah = [
        {
            "title": "1. Rumus Enkripsi",
            "desc": f"Setiap huruf digeser maju sebanyak {key} posisi: C = (P + K) mod 26."
        },
        {
            "title": "2. Proses Setiap Karakter",
            "table": detail_proses
        },
        {
            "title": "3. Ciphertext",
            "code": hasil
        }
    ]
    return hasil, langkah

def caesar_decrypt(text, key):
    hasil, detail_proses = caesar_chiper(text, key, True)
    langkah = [
        {
            "title": "1. Rumus Dekripsi",
            "desc": f"Setiap huruf digeser mundur sebanyak {key} posisi: P = (C - K) mod 26."
        },
        {
            "title": "2. Proses Setiap Karakter",
            "table": detail_proses
        },
        {
            "title": "3. Plaintext",
            "code": hasil
        }
    ]
    return hasil, langkah