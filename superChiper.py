import caesarChiper as cc
import railfenceChiper as rf
import streamChiperLFSR as sc
import blockChiper as bc

def super_encrypt(plaintext, caesar_shift, rail_count, lfsr_seed, block_key):
    # 1. Caesar
    step1, lang_c = cc.enkripsi_caesar(plaintext, caesar_shift)
    # 2. Rail Fence
    step2, lang_r = rf.enkripsi_rail_fence(step1, rail_count)
    # 3. Stream LFSR
    step3_hex, lang_s = sc.stream_encrypt(step2, str(lfsr_seed))
    # 4. Block Feistel
    final_hex, lang_b = bc.enkripsi_block(step3_hex, block_key)

    stages = [
        ("Tahap 1: Caesar Cipher", plaintext, step1, lang_c),
        ("Tahap 2: Rail Fence Cipher", step1, step2, lang_r),
        ("Tahap 3: Stream Cipher (LFSR)", step2, step3_hex, lang_s),
        ("Tahap 4: Block Cipher (Feistel)", step3_hex, final_hex, lang_b)
    ]
    return final_hex, stages

def super_decrypt(ciphertext_hex, caesar_shift, rail_count, lfsr_seed, block_key):
    # 1. Block Feistel
    step3_hex, lang_b = bc.dekripsi_block(ciphertext_hex, block_key)
    # 2. Stream LFSR
    step2, lang_s = sc.stream_decrypt(step3_hex, str(lfsr_seed))
    # 3. Rail Fence
    step1, lang_r = rf.dekripsi_rail_fence(step2, rail_count)
    # 4. Caesar
    plaintext, lang_c = cc.caesar_decrypt(step1, caesar_shift)

    stages = [
        ("Tahap 1: Block Cipher (Feistel) Decrypt", ciphertext_hex, step3_hex, lang_b),
        ("Tahap 2: Stream Cipher (LFSR) Decrypt", step3_hex, step2, lang_s),
        ("Tahap 3: Rail Fence Cipher Decrypt", step2, step1, lang_r),
        ("Tahap 4: Caesar Cipher Decrypt", step1, plaintext, lang_c)
    ]
    return plaintext, stages