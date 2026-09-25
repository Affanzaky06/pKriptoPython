# RAIL FENCE CHIPER
def enkripsi_rail_fence(text, key):
    if key < 2:
        raise ValueError("Jumlah rail minimal 2.")
    if text == "":
        raise ValueError("Teks tidak boleh kosong.")

    # Menghapus spasi dari plaintext 
    text = "".join(text.split())

    jumlah_karakter = len(text)
    matriks = []

    for i in range(key): 
        baris = [] 
        for j in range(jumlah_karakter): 
            baris.append(".") 
        matriks.append(baris)

    # Posisi awal berada di rail pertama 
    nomor_rail = 0 
    kolom = 0 
    arah_turun = True

    # Menempatkan setiap karakter ke dalam pola zig-zag 
    for i in range(jumlah_karakter): 
        # Mengisi karakter ke matriks 
        matriks[nomor_rail][kolom] = text[i] 
        kolom += 1 
        
        # Jika berada di rail paling atas, arah harus turun 
        if nomor_rail == 0: 
            arah_turun = True 
        
        # Jika berada di rail paling bawah, arah harus naik 
        elif nomor_rail == key - 1: 
            arah_turun = False 
            
        # Mengatur perpindahan rail 
        if arah_turun: 
            nomor_rail += 1 
        else: 
            nomor_rail -= 1

    # Menampilkan informasi teks 
    print("=== INFORMASI TEKS ===") 
    print(f"Jumlah karakter : {jumlah_karakter}") 
    print(f"Kunci Rail Fence: {key}")

    # Menampilkan pola Rail Fence 
    print("\n=== POLA SUSUNAN RAIL FENCE ===") 
    
    for nomor_baris in range(key): 
        print(f"Rail {nomor_baris + 1}: ", end="") 
        
        for nomor_kolom in range(jumlah_karakter): 
            print(matriks[nomor_baris][nomor_kolom], end=" ") 
            print() 
    
    # Membaca karakter dari setiap rail 
    print("\n=== CIPHERTEXT PER RAIL ===")
    ciphertext = "" 
    
    for nomor_baris in range(key): 
        rail_text = "" 

        for nomor_kolom in range(jumlah_karakter): 
            karakter = matriks[nomor_baris][nomor_kolom] 
            if karakter != ".": 
                rail_text += karakter  
        print(f"Rail {nomor_baris + 1} = {rail_text}") 
        ciphertext += rail_text 
        
    # Menampilkan ciphertext akhir 
    print("\n=== TEKS HASIL ENKRIPSI RAIL FENCE ===") 
    print(ciphertext) 
    print(f"Jumlah karakter : {len(ciphertext)}") 
    return ciphertext

def dekripsi_rail_fence(ciphertext, key): 
    # Validasi jumlah rail 
    if key < 2: 
        raise ValueError("Jumlah rail minimal 2.") 
    if ciphertext == "": 
        raise ValueError("Ciphertext tidak boleh kosong.") 
    
    jumlah_karakter = len(ciphertext) 
    matriks = [] 
        
    for i in range(key): 
        baris = [] 
        for j in range(jumlah_karakter): 
            baris.append(".") 
        matriks.append(baris) 
                
    # Membuat pola zig-zag 
    nomor_rail = 0 
    kolom = 0 
    arah_turun = True 
        
    for i in range(jumlah_karakter): 
        # Menandai posisi yang akan diisi 
        matriks[nomor_rail][kolom] = "*" 
        kolom += 1 
        
        if nomor_rail == 0: 
            arah_turun = True 
        elif nomor_rail == key - 1: 
            arah_turun = False 
            
        if arah_turun: 
            nomor_rail += 1 
        else: nomor_rail -= 1 
            
    # Mengisi ciphertext ke posisi yang sudah ditandai 
    posisi_ciphertext = 0 
        
    for nomor_baris in range(key): 
        for nomor_kolom in range(jumlah_karakter): 
            if matriks[nomor_baris][nomor_kolom] == "*": 
                matriks[nomor_baris][nomor_kolom] = ciphertext[posisi_ciphertext]
                posisi_ciphertext += 1 
        
    # Membaca kembali matriks secara zig-zag 
    plaintext = "" 
    nomor_rail = 0 
    kolom = 0 
    arah_turun = True 
        
    for i in range(jumlah_karakter): 
        plaintext += matriks[nomor_rail][kolom] 
        kolom += 1 
        
        if nomor_rail == 0: 
            arah_turun = True 
        elif nomor_rail == key - 1: 
            arah_turun = False 
            
        if arah_turun: 
            nomor_rail += 1 
        else: nomor_rail -= 1 
            
    # Menampilkan hasil dekripsi 
    print("\n=== HASIL DEKRIPSI RAIL FENCE ===") 
    print(plaintext) 
    print(f"Jumlah karakter : {len(plaintext)}") 
    
    return plaintext