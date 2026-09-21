from crypto_algos import *
import random, string

# Contoh dari slide: LFSR 4-bit seed 1111 -> 1 1 1 1 0 1 0 1 1 0 0 1 0 0 0
l = LFSR([1,1,1,1]); seq = "".join(str(l.next_bit()[0]) for _ in range(15))
assert seq == "111101011001000", seq
# rail fence klasik
assert railfence_encrypt("WEAREDISCOVEREDFLEEATONCE", 3)[0] == "WECRLTEERDSOEEFEAOCAIVDEN"
assert caesar_encrypt("Hello, World!", 3)[0] == "Khoor, Zruog!"

texts = ["Halo Dunia!", "A", "INponya 123 — ünïcode ✓", "x"*50, "ab"]
for t in texts:
    for sh in (0, 3, 25, 29):
        assert caesar_decrypt(caesar_encrypt(t, sh)[0], sh)[0] == t
    for r in (2, 3, 5, 100):
        assert railfence_decrypt(railfence_encrypt(t, r)[0], r)[0] == t
    for seed in ("1111", "1010101", "1100110011001100"):
        assert stream_decrypt(stream_encrypt(t, seed)[0], seed)[0] == t
    for k in ("k", "kunci", "kuncipanjangbanget"):
        assert block_decrypt(block_encrypt(t, k)[0], k)[0] == t
    c, st = super_encrypt(t, 7, 4, "1011", "rahasia")
    p, st2 = super_decrypt(c, 7, 4, "1011", "rahasia")
    assert p == t, (t, p)
# kunci salah harus ditolak/berbeda
c = block_encrypt("Halo Dunia!", "abc")[0]
try:
    r = block_decrypt(c, "abd")[0]; print("kunci salah ->", repr(r))
except ValueError as e: print("OK error:", e)
for bad in [("ZZ","1111"),("AB","0000"),("AB","12")]:
    try: stream_decrypt(*bad); print("tidak error?", bad)
    except ValueError as e: print("OK:", e)
print("SEMUA TES LULUS")
