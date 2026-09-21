"""
Modul algoritma kriptografi.

Setiap fungsi mengembalikan (hasil, steps) dengan steps berupa list dict:
    {"title": str, "desc": str (opsional), "table": list[dict] (opsional), "code": str (opsional)}
Steps inilah yang ditampilkan di halaman "Proses Algoritma".
"""

# ======================================================================
# 1. CAESAR CIPHER (klasik)
# ======================================================================

def _caesar(text, shift, decrypt=False):
    s = (-shift if decrypt else shift) % 26
    out, rows = [], []
    for ch in text:
        if ch.isalpha() and ch.isascii():
            base = ord("A") if ch.isupper() else ord("a")
            x = ord(ch) - base
            y = (x + s) % 26
            r = chr(base + y)
            op = "-" if decrypt else "+"
            rumus = f"({x} {op} {shift % 26}) mod 26 = {y}"
            rows.append({"Karakter": ch, "Posisi (0-25)": x, "Rumus": rumus, "Hasil": r})
        else:
            r = ch
            rows.append({"Karakter": ch, "Posisi (0-25)": "-", "Rumus": "bukan huruf, tidak diubah", "Hasil": r})
        out.append(r)
    return "".join(out), rows


def caesar_encrypt(text, shift):
    result, rows = _caesar(text, shift, False)
    steps = [
        {"title": "1. Rumus enkripsi",
         "desc": f"Setiap huruf digeser sebanyak **{shift}** posisi: `C = (P + K) mod 26`. "
                 "Huruf kapital/kecil dipertahankan, karakter non-huruf tidak diubah."},
        {"title": "2. Proses per karakter", "table": rows},
        {"title": "3. Ciphertext", "code": result},
    ]
    return result, steps


def caesar_decrypt(text, shift):
    result, rows = _caesar(text, shift, True)
    steps = [
        {"title": "1. Rumus dekripsi",
         "desc": f"Setiap huruf digeser mundur sebanyak **{shift}** posisi: `P = (C - K) mod 26`."},
        {"title": "2. Proses per karakter", "table": rows},
        {"title": "3. Plaintext", "code": result},
    ]
    return result, steps


# ======================================================================
# 2. RAIL FENCE CIPHER (klasik, transposisi)
# ======================================================================

def _rail_pattern(n, rails):
    """Nomor rail untuk tiap posisi karakter (zig-zag)."""
    if rails < 2:
        return [0] * n
    pattern, r, d = [], 0, 1
    for _ in range(n):
        pattern.append(r)
        if r == 0:
            d = 1
        elif r == rails - 1:
            d = -1
        r += d
    return pattern


def _rail_grid(chars, pattern, rails):
    lines = []
    for r in range(rails):
        lines.append(" ".join(chars[i] if pattern[i] == r else "." for i in range(len(chars))))
    return "\n".join(f"Rail {r + 1}: {line}" for r, line in enumerate(lines))


def _check_rails(text, rails):
    if rails < 2:
        raise ValueError("Jumlah rail minimal 2.")
    if len(text) == 0:
        raise ValueError("Teks tidak boleh kosong.")


def railfence_encrypt(text, rails):
    _check_rails(text, rails)
    n = len(text)
    eff = min(rails, n)
    pattern = _rail_pattern(n, eff) if eff >= 2 else [0] * n
    chars = list(text)
    rows = ["".join(chars[i] for i in range(n) if pattern[i] == r) for r in range(eff)]
    result = "".join(rows)
    steps = [
        {"title": "1. Tulis plaintext secara zig-zag",
         "desc": f"Plaintext ditulis diagonal naik-turun pada **{eff} rail**. Tanda `.` = kotak kosong.",
         "code": _rail_grid(chars, pattern, eff)},
        {"title": "2. Baca per rail (kiri ke kanan, rail 1 → terakhir)",
         "table": [{"Rail": r + 1, "Karakter": rows[r]} for r in range(eff)]},
        {"title": "3. Gabungkan = Ciphertext", "code": result},
    ]
    return result, steps


def railfence_decrypt(text, rails):
    _check_rails(text, rails)
    n = len(text)
    eff = min(rails, n)
    pattern = _rail_pattern(n, eff) if eff >= 2 else [0] * n
    # urutan posisi ketika dibaca per rail
    order = sorted(range(n), key=lambda i: (pattern[i], i))
    plain = [""] * n
    for ch, pos in zip(text, order):
        plain[pos] = ch
    result = "".join(plain)
    # panjang tiap rail
    lens = [pattern.count(r) for r in range(eff)]
    idx, rows = 0, []
    for r in range(eff):
        rows.append({"Rail": r + 1, "Jumlah karakter": lens[r], "Ciphertext yang diisikan": text[idx:idx + lens[r]]})
        idx += lens[r]
    steps = [
        {"title": "1. Tentukan pola zig-zag",
         "desc": f"Panjang teks {n}, **{eff} rail**. Pola zig-zag sama seperti saat enkripsi; "
                 "kotak yang akan terisi ditandai `*`.",
         "code": "\n".join(f"Rail {r + 1}: " + " ".join("*" if pattern[i] == r else "." for i in range(n))
                           for r in range(eff))},
        {"title": "2. Bagi ciphertext ke tiap rail", "table": rows},
        {"title": "3. Isi kotak per rail, lalu baca zig-zag",
         "code": _rail_grid(plain, pattern, eff)},
        {"title": "4. Plaintext", "code": result},
    ]
    return result, steps


# ======================================================================
# 3. STREAM CIPHER dengan LFSR (modern, dari Materi 5)
#    ci = pi XOR ki ; keystream dibangkitkan oleh LFSR
# ======================================================================

# tap (nomor bit, 1 = b1) untuk fungsi umpan balik; semuanya periode maksimal 2^n - 1
# n=4 memakai b4 = b1 XOR b4 seperti contoh di slide
LFSR_TAPS = {
    4: (1, 4), 5: (1, 3), 6: (1, 2), 7: (1, 2), 8: (1, 2, 3, 8), 9: (1, 5),
    10: (1, 4), 11: (1, 3), 12: (1, 2, 3, 9), 13: (1, 2, 3, 6), 14: (1, 2, 3, 13),
    15: (1, 2), 16: (1, 2, 4, 13),
}


def _parse_seed(seed):
    seed = seed.strip()
    if not seed or any(c not in "01" for c in seed):
        raise ValueError("Kunci LFSR harus berupa bit (hanya 0 dan 1), contoh: 1111")
    if not 4 <= len(seed) <= 16:
        raise ValueError("Panjang kunci LFSR harus 4 sampai 16 bit.")
    if "1" not in seed:
        raise ValueError("Kunci LFSR tidak boleh semua nol.")
    return [int(c) for c in seed]


class LFSR:
    def __init__(self, seed_bits):
        self.n = len(seed_bits)
        self.taps = LFSR_TAPS[self.n]
        self.reg = list(seed_bits)

    def next_bit(self):
        out = self.reg[0]                       # b1 keluar sebagai bit keystream
        fb = 0
        for t in self.taps:
            fb ^= self.reg[t - 1]
        self.reg = self.reg[1:] + [fb]          # geser kiri, umpan balik masuk sebagai b_n
        return out, fb


def _bits(byte):
    return format(byte, "08b")


def _lfsr_trace(seed_bits, count=16):
    l = LFSR(seed_bits)
    rows = []
    for i in range(1, count + 1):
        before = "".join(map(str, l.reg))
        out, fb = l.next_bit()
        rows.append({"Langkah": i, "Register (b1..bn)": before, "Bit keluar (b1)": out,
                     "Umpan balik": fb, "Register baru": "".join(map(str, l.reg))})
    return rows


def _stream_xor(data, seed_bits):
    l = LFSR(seed_bits)
    out, rows = bytearray(), []
    for b in data:
        k = 0
        for _ in range(8):
            k = (k << 1) | l.next_bit()[0]
        c = b ^ k
        out.append(c)
        rows.append({"Byte": chr(b) if 32 <= b < 127 else f"0x{b:02X}", "Input (bin)": _bits(b),
                     "Keystream (bin)": _bits(k), "Output (bin)": _bits(c), "Output (hex)": f"{c:02X}"})
    return bytes(out), rows


def _lfsr_info_step(seed_bits):
    n = len(seed_bits)
    taps = LFSR_TAPS[n]
    rumus = " ⊕ ".join(f"b{t}" for t in taps)
    return {"title": "1. Konfigurasi LFSR",
            "desc": f"Register **{n} bit**, seed (kunci) = `{''.join(map(str, seed_bits))}`. "
                    f"Fungsi umpan balik: `b{n} = {rumus}`. Periode maksimum = 2^{n} − 1 = **{2 ** n - 1} bit**."
                    + (" ⚠️ Periode pendek: keystream cepat berulang (mirip XOR sederhana, kurang aman)."
                       if n < 12 else "")}


def stream_encrypt(text, seed):
    bits = _parse_seed(seed)
    data = text.encode("utf-8")
    if not data:
        raise ValueError("Plaintext tidak boleh kosong.")
    out, rows = _stream_xor(data, bits)
    steps = [
        _lfsr_info_step(bits),
        {"title": "2. Pembangkitan keystream (16 langkah pertama)",
         "desc": "Setiap langkah: bit `b1` keluar sebagai bit keystream, register digeser kiri, "
                 "hasil umpan balik masuk di posisi terakhir.",
         "table": _lfsr_trace(bits)},
        {"title": "3. Enkripsi XOR per byte: `Ci = Pi ⊕ Ki`",
         "desc": "Tiap byte plaintext di-XOR dengan 8 bit keystream.", "table": rows},
        {"title": "4. Ciphertext (hex)", "code": out.hex().upper()},
    ]
    return out.hex().upper(), steps


def _parse_hex(hex_text):
    h = "".join(hex_text.split())
    try:
        return bytes.fromhex(h)
    except ValueError:
        raise ValueError("Ciphertext harus berupa string heksadesimal (0-9, A-F) dengan panjang genap.")


def stream_decrypt(hex_text, seed):
    bits = _parse_seed(seed)
    data = _parse_hex(hex_text)
    if not data:
        raise ValueError("Ciphertext tidak boleh kosong.")
    out, rows = _stream_xor(data, bits)
    try:
        plain = out.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Hasil dekripsi bukan teks UTF-8 yang valid. Kunci kemungkinan salah.")
    steps = [
        _lfsr_info_step(bits),
        {"title": "2. Pembangkitan keystream (16 langkah pertama)",
         "desc": "Keystream harus identik dengan saat enkripsi (kunci sama).", "table": _lfsr_trace(bits)},
        {"title": "3. Dekripsi XOR per byte: `Pi = Ci ⊕ Ki`",
         "desc": "XOR ciphertext dengan keystream yang sama mengembalikan plaintext (karena K ⊕ K = 0).",
         "table": rows},
        {"title": "4. Plaintext", "code": plain},
    ]
    return plain, steps


# ======================================================================
# 4. BLOCK CIPHER - Jaringan Feistel 64-bit (modern, dari Materi 5)
#    Blok 64 bit = 8 karakter, kunci 64 bit, 8 putaran, padding PKCS#7
# ======================================================================

BLOCK_SIZE = 8
ROUNDS = 8
M32 = 0xFFFFFFFF


def _rotl32(x, r):
    return ((x << r) | (x >> (32 - r))) & M32


def _rotl64(x, r):
    return ((x << r) | (x >> (64 - r))) & 0xFFFFFFFFFFFFFFFF


def _key64(key):
    if not key:
        raise ValueError("Kunci block cipher tidak boleh kosong.")
    kb = key.encode("utf-8")
    kb = (kb * (BLOCK_SIZE // len(kb) + 1))[:BLOCK_SIZE]   # ulang/potong jadi 8 byte (64 bit)
    return int.from_bytes(kb, "big"), kb


def _round_keys(key):
    k64, kb = _key64(key)
    rks = []
    for i in range(ROUNDS):
        rk = (_rotl64(k64, 7 * (i + 1)) >> 32) ^ (((i + 1) * 0x9E3779B9) & M32)
        rks.append(rk)
    return rks, kb


def _F(r, k):
    return _rotl32(((r ^ k) * 0x045D9F3B) & M32, 13)


def _feistel(block, rks, trace=None):
    L, R = (block >> 32) & M32, block & M32
    for i, k in enumerate(rks):
        f = _F(R, k)
        newR = L ^ f
        if trace is not None:
            trace.append({"Putaran": i + 1, "L": f"{L:08X}", "R": f"{R:08X}", "Kunci putaran": f"{k:08X}",
                          "F(R,K)": f"{f:08X}", "L baru (=R)": f"{R:08X}", "R baru (=L ⊕ F)": f"{newR:08X}"})
        L, R = R, newR
    return (R << 32) | L        # tukar L dan R di akhir


def _pad(data):
    n = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([n]) * n, n


def _blocks(data):
    return [data[i:i + BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]


def _key_steps(key, rks, kb):
    return {"title": "1. Kunci & round key",
            "desc": f"Kunci `{key}` diubah menjadi 64 bit (diulang/dipotong menjadi 8 byte): `{kb.hex().upper()}`. "
                    f"Dari kunci ini dibangkitkan {ROUNDS} round key 32-bit.",
            "table": [{"Putaran": i + 1, "Round key": f"{k:08X}"} for i, k in enumerate(rks)]}


def block_encrypt(text, key):
    data = text.encode("utf-8")
    if not data:
        raise ValueError("Plaintext tidak boleh kosong.")
    rks, kb = _round_keys(key)
    padded, n = _pad(data)
    blocks = _blocks(padded)
    out, summary, first_trace = b"", [], []
    for bi, b in enumerate(blocks):
        v = int.from_bytes(b, "big")
        c = _feistel(v, rks, first_trace if bi == 0 else None)
        cb = c.to_bytes(BLOCK_SIZE, "big")
        out += cb
        summary.append({"Blok": bi + 1, "Plaintext (hex)": b.hex().upper(), "Ciphertext (hex)": cb.hex().upper()})
    steps = [
        _key_steps(key, rks, kb),
        {"title": "2. Padding & pembagian blok",
         "desc": f"Plaintext = {len(data)} byte. Blok = 64 bit (8 byte), ditambah **{n} byte padding** "
                 f"(nilai `{n:02X}`) sehingga menjadi {len(blocks)} blok.",
         "table": [{"Blok": i + 1, "Isi (hex)": b.hex().upper()} for i, b in enumerate(blocks)]},
        {"title": "3. Jaringan Feistel pada blok 1",
         "desc": "Tiap putaran: `L' = R`, `R' = L ⊕ F(R, K)`. Setelah 8 putaran, L dan R ditukar.",
         "table": first_trace},
        {"title": "4. Hasil semua blok (mode ECB)", "table": summary},
        {"title": "5. Ciphertext (hex)", "code": out.hex().upper()},
    ]
    return out.hex().upper(), steps


def block_decrypt(hex_text, key):
    data = _parse_hex(hex_text)
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Panjang ciphertext harus kelipatan 8 byte (16 karakter hex).")
    rks, kb = _round_keys(key)
    rev = rks[::-1]
    out, summary, first_trace = b"", [], []
    for bi, b in enumerate(_blocks(data)):
        v = int.from_bytes(b, "big")
        p = _feistel(v, rev, first_trace if bi == 0 else None)
        pb = p.to_bytes(BLOCK_SIZE, "big")
        out += pb
        summary.append({"Blok": bi + 1, "Ciphertext (hex)": b.hex().upper(), "Hasil (hex)": pb.hex().upper()})
    n = out[-1]
    if not 1 <= n <= BLOCK_SIZE or out[-n:] != bytes([n]) * n:
        raise ValueError("Padding tidak valid. Kunci kemungkinan salah atau ciphertext rusak.")
    plain_bytes = out[:-n]
    try:
        plain = plain_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Hasil dekripsi bukan teks UTF-8 yang valid. Kunci kemungkinan salah.")
    steps = [
        _key_steps(key, rks, kb),
        {"title": "2. Pembagian blok ciphertext",
         "table": [{"Blok": i + 1, "Isi (hex)": b.hex().upper()} for i, b in enumerate(_blocks(data))]},
        {"title": "3. Jaringan Feistel pada blok 1 (round key dipakai terbalik)",
         "desc": "Dekripsi memakai struktur yang sama, hanya urutan round key dibalik.", "table": first_trace},
        {"title": "4. Hasil semua blok", "table": summary},
        {"title": "5. Hapus padding",
         "desc": f"Byte terakhir bernilai `{n:02X}` → buang {n} byte padding."},
        {"title": "6. Plaintext", "code": plain},
    ]
    return plain, steps


# ======================================================================
# 5. SUPER ENKRIPSI = Caesar -> Rail Fence -> Stream (LFSR) -> Block (Feistel)
# ======================================================================

def super_encrypt(text, shift, rails, seed, key):
    if not text:
        raise ValueError("Plaintext tidak boleh kosong.")
    stages = []
    s1, st1 = caesar_encrypt(text, shift)
    stages.append(("Tahap 1 - Caesar Cipher", text, s1, st1))
    s2, st2 = railfence_encrypt(s1, rails)
    stages.append(("Tahap 2 - Rail Fence Cipher", s1, s2, st2))
    s3, st3 = stream_encrypt(s2, seed)
    stages.append(("Tahap 3 - Stream Cipher (LFSR)", s2, s3, st3))
    s4, st4 = block_encrypt_hex(s3, key)
    stages.append(("Tahap 4 - Block Cipher (Feistel)", s3, s4, st4))
    return s4, stages


def block_encrypt_hex(hex_text, key):
    """Block cipher yang inputnya hex hasil tahap sebelumnya (byte, bukan teks)."""
    data = _parse_hex(hex_text)
    rks, kb = _round_keys(key)
    padded, n = _pad(data)
    blocks = _blocks(padded)
    out, summary, first_trace = b"", [], []
    for bi, b in enumerate(blocks):
        c = _feistel(int.from_bytes(b, "big"), rks, first_trace if bi == 0 else None)
        cb = c.to_bytes(BLOCK_SIZE, "big")
        out += cb
        summary.append({"Blok": bi + 1, "Input (hex)": b.hex().upper(), "Ciphertext (hex)": cb.hex().upper()})
    steps = [
        _key_steps(key, rks, kb),
        {"title": "2. Padding & pembagian blok",
         "desc": f"Input = {len(data)} byte, ditambah **{n} byte padding** → {len(blocks)} blok 64-bit.",
         "table": [{"Blok": i + 1, "Isi (hex)": b.hex().upper()} for i, b in enumerate(blocks)]},
        {"title": "3. Jaringan Feistel pada blok 1", "table": first_trace},
        {"title": "4. Hasil semua blok (mode ECB)", "table": summary},
        {"title": "5. Ciphertext (hex)", "code": out.hex().upper()},
    ]
    return out.hex().upper(), steps


def block_decrypt_hex(hex_text, key):
    """Kebalikan block_encrypt_hex: hasilnya hex byte (belum diterjemahkan ke teks)."""
    data = _parse_hex(hex_text)
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Panjang ciphertext harus kelipatan 8 byte (16 karakter hex).")
    rks, kb = _round_keys(key)
    rev = rks[::-1]
    out, summary, first_trace = b"", [], []
    for bi, b in enumerate(_blocks(data)):
        p = _feistel(int.from_bytes(b, "big"), rev, first_trace if bi == 0 else None)
        pb = p.to_bytes(BLOCK_SIZE, "big")
        out += pb
        summary.append({"Blok": bi + 1, "Ciphertext (hex)": b.hex().upper(), "Hasil (hex)": pb.hex().upper()})
    n = out[-1]
    if not 1 <= n <= BLOCK_SIZE or out[-n:] != bytes([n]) * n:
        raise ValueError("Padding tidak valid. Kunci block cipher kemungkinan salah atau ciphertext rusak.")
    res = out[:-n].hex().upper()
    steps = [
        _key_steps(key, rks, kb),
        {"title": "2. Jaringan Feistel pada blok 1 (round key terbalik)", "table": first_trace},
        {"title": "3. Hasil semua blok", "table": summary},
        {"title": "4. Hapus padding", "desc": f"Buang {n} byte padding (`{n:02X}`)."},
        {"title": "5. Hasil (hex)", "code": res},
    ]
    return res, steps


def super_decrypt(hex_text, shift, rails, seed, key):
    stages = []
    s1, st1 = block_decrypt_hex(hex_text, key)
    stages.append(("Tahap 1 - Dekripsi Block Cipher (Feistel)", hex_text, s1, st1))
    s2, st2 = stream_decrypt(s1, seed)
    stages.append(("Tahap 2 - Dekripsi Stream Cipher (LFSR)", s1, s2, st2))
    s3, st3 = railfence_decrypt(s2, rails)
    stages.append(("Tahap 3 - Dekripsi Rail Fence Cipher", s2, s3, st3))
    s4, st4 = caesar_decrypt(s3, shift)
    stages.append(("Tahap 4 - Dekripsi Caesar Cipher", s3, s4, st4))
    return s4, stages
