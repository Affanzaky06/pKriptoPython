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
    order = sorted(range(n), key=lambda i: (pattern[i], i))
    plain = [""] * n
    for ch, pos in zip(text, order):
        plain[pos] = ch
    result = "".join(plain)
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


def _parse_hex(hex_text):
    h = "".join(hex_text.split())
    try:
        return bytes.fromhex(h)
    except ValueError:
        raise ValueError("Ciphertext harus berupa string heksadesimal (0-9, A-F) dengan panjang genap.")


# ======================================================================
# 3. STREAM CIPHER dengan LFSR (modern, dari Materi 5 slide 14-32)
#    ci = pi XOR ki ; keystream dibangkitkan oleh LFSR (keystream generator)
# ======================================================================

# tap (nomor bit, 1 = b1) untuk fungsi umpan balik; semuanya periode maksimal 2^n - 1
# n=4 memakai b4 = b1 XOR b4 seperti contoh di slide (U = 1111)
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
    return {"title": "1. Konfigurasi LFSR (keystream generator)",
            "desc": f"Register **{n} bit**, seed (kunci U) = `{''.join(map(str, seed_bits))}`. "
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
# 4. XOR SEDERHANA (modern, dari Materi 5 slide 12-13)
#    C = P XOR K, kunci diulang secara periodik (prinsip sama seperti Vigenere,
#    tapi dalam mode bit). PPT juga menyebut algoritma ini kurang aman karena
#    cipherteksnya mudah dipecahkan bila kunci dipakai berulang.
# ======================================================================

def _xor_bytes(data, key):
    if not key:
        raise ValueError("Kunci tidak boleh kosong.")
    kb = key.encode("utf-8")
    key_full = bytes(kb[i % len(kb)] for i in range(len(data)))
    out = bytes(d ^ k for d, k in zip(data, key_full))
    rows = []
    for i, (d, k, c) in enumerate(zip(data, key_full, out), start=1):
        rows.append({
            "Ke-": i,
            "Plaintext": chr(d) if 32 <= d < 127 else f"0x{d:02X}",
            "Kunci (diulang)": chr(k) if 32 <= k < 127 else f"0x{k:02X}",
            "P (bin)": _bits(d), "K (bin)": _bits(k), "C (bin)": _bits(c), "C (hex)": f"{c:02X}",
        })
    return out, key_full, rows


def _xor_key_step(key, key_full):
    return {"title": "1. Ulangi kunci secara periodik",
            "desc": f"Kunci `{key}` ({len(key.encode('utf-8'))} byte) diulang terus sampai sepanjang data "
                    f"({len(key_full)} byte), mirip Vigenère cipher tapi dalam mode bit.",
            "code": key_full.decode("latin1")}


def xor_encrypt(text, key):
    data = text.encode("utf-8")
    if not data:
        raise ValueError("Plaintext tidak boleh kosong.")
    out, key_full, rows = _xor_bytes(data, key)
    steps = [
        _xor_key_step(key, key_full),
        {"title": "2. XOR tiap byte: `C = P ⊕ K`", "table": rows},
        {"title": "3. Ciphertext (hex)", "code": out.hex().upper()},
    ]
    return out.hex().upper(), steps


def xor_decrypt(hex_text, key):
    data = _parse_hex(hex_text)
    if not data:
        raise ValueError("Ciphertext tidak boleh kosong.")
    out, key_full, rows = _xor_bytes(data, key)
    try:
        plain = out.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Hasil dekripsi bukan teks UTF-8 yang valid. Kunci kemungkinan salah.")
    steps = [
        _xor_key_step(key, key_full),
        {"title": "2. XOR tiap byte: `P = C ⊕ K`",
         "desc": "Operasi sama seperti enkripsi karena `(P ⊕ K) ⊕ K = P`.", "table": rows},
        {"title": "3. Plaintext", "code": plain},
    ]
    return plain, steps


def xor_encrypt_hex(hex_text, key):
    """Versi XOR sederhana untuk input berupa hex byte (dipakai di rantai super enkripsi)."""
    data = _parse_hex(hex_text)
    if not data:
        raise ValueError("Data tidak boleh kosong.")
    out, key_full, rows = _xor_bytes(data, key)
    steps = [
        _xor_key_step(key, key_full),
        {"title": "2. XOR tiap byte: `C = P ⊕ K`", "table": rows},
        {"title": "3. Hasil (hex)", "code": out.hex().upper()},
    ]
    return out.hex().upper(), steps


def xor_decrypt_hex(hex_text, key):
    """Kebalikan xor_encrypt_hex; hasilnya tetap hex (belum diterjemahkan ke teks)."""
    data = _parse_hex(hex_text)
    if not data:
        raise ValueError("Data tidak boleh kosong.")
    out, key_full, rows = _xor_bytes(data, key)
    steps = [
        _xor_key_step(key, key_full),
        {"title": "2. XOR tiap byte: `P = C ⊕ K`", "table": rows},
        {"title": "3. Hasil (hex)", "code": out.hex().upper()},
    ]
    return out.hex().upper(), steps


# ======================================================================
# 5. SUPER ENKRIPSI = Caesar -> Rail Fence -> Stream (LFSR) -> XOR Sederhana
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
    s4, st4 = xor_encrypt_hex(s3, key)
    stages.append(("Tahap 4 - XOR Sederhana", s3, s4, st4))
    return s4, stages


def super_decrypt(hex_text, shift, rails, seed, key):
    stages = []
    s1, st1 = xor_decrypt_hex(hex_text, key)
    stages.append(("Tahap 1 - Dekripsi XOR Sederhana", hex_text, s1, st1))
    s2, st2 = stream_decrypt(s1, seed)
    stages.append(("Tahap 2 - Dekripsi Stream Cipher (LFSR)", s1, s2, st2))
    s3, st3 = railfence_decrypt(s2, rails)
    stages.append(("Tahap 3 - Dekripsi Rail Fence Cipher", s2, s3, st3))
    s4, st4 = caesar_decrypt(s3, shift)
    stages.append(("Tahap 4 - Dekripsi Caesar Cipher", s3, s4, st4))
    return s4, stages