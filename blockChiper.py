import hashlib

BLOCK_SIZE = 8      # 8 byte = 64 bit
NUM_ROUNDS = 8      # jumlah ronde Feistel

def _derive_subkeys(key: str, rounds: int = NUM_ROUNDS):
    subkeys = []
    material = key.encode("utf-8")
    for i in range(rounds):
        h = hashlib.sha256(material + bytes([i])).digest()
        subkeys.append(h[0])
    return subkeys

def _F(half_block: bytes, subkey: int) -> bytes:
    result = bytearray()
    for i, b in enumerate(half_block):
        val = (b ^ subkey ^ (i * 7 + 1)) & 0xFF
        val = ((val << 3) | (val >> 5)) & 0xFF
        result.append(val)
    return bytes(result)

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def _pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0: pad_len = block_size
    return data + bytes([pad_len] * pad_len)

def _unpad(data: bytes) -> bytes:
    if not data: return data
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BLOCK_SIZE:
        return data
    return data[:-pad_len]

def _encrypt_block(block: bytes, subkeys) -> bytes:
    half = len(block) // 2
    L, R = block[:half], block[half:]
    for sk in subkeys:
        f_out = _F(R, sk)
        new_R = _xor_bytes(L, f_out[:len(L)])
        L, R = R, new_R
    return L + R

def _decrypt_block(block: bytes, subkeys) -> bytes:
    half = len(block) // 2
    L, R = block[:half], block[half:]
    for sk in reversed(subkeys):
        f_out = _F(L, sk)
        new_L = _xor_bytes(R, f_out[:len(R)])
        R, L = L, new_L
    return L + R

def block_cipher_encrypt(plaintext: str, key: str) -> bytes:
    subkeys = _derive_subkeys(key)
    data = _pad(plaintext.encode("utf-8"))
    out = bytearray()
    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        out.extend(_encrypt_block(block, subkeys))
    return bytes(out)

def block_cipher_decrypt(ciphertext: bytes, key: str) -> str:
    subkeys = _derive_subkeys(key)
    out = bytearray()
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        out.extend(_decrypt_block(block, subkeys))
    data = _unpad(bytes(out))
    return data.decode("utf-8", errors="ignore")

# --- WRAPPER UNTUK STREAMLIT ---
def enkripsi_block(text, key):
    ct_bytes = block_cipher_encrypt(text, key)
    ct_hex = ct_bytes.hex().upper()
    langkah = [
        {"title": "1. Derivasi Kunci", "desc": f"Membuat {NUM_ROUNDS} subkeys dari kunci '{key}'."},
        {"title": "2. Padding & Feistel Network", "desc": "Teks dibagi per 8 byte, diproses 8 ronde L dan R."},
        {"title": "3. Ciphertext (Hex)", "code": ct_hex}
    ]
    return ct_hex, langkah

def dekripsi_block(ct_hex, key):
    # Bersihkan spasi jika ada
    ct_hex = "".join(ct_hex.split())
    ct_bytes = bytes.fromhex(ct_hex)
    pt = block_cipher_decrypt(ct_bytes, key)
    langkah = [
        {"title": "1. Dekripsi Feistel Network", "desc": "Merapikan blok dengan subkeys urutan terbalik."},
        {"title": "2. Unpad & Teks Asli", "code": pt}
    ]
    return pt, langkah