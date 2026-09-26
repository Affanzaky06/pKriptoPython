import pandas as pd
import streamlit as st

import crypto_algos as ca

st.set_page_config(page_title="Aplikasi Kriptografi", page_icon="🔐", layout="wide")

MENUS = [
    "1. Caesar Cipher",
    "2. Rail Fence Cipher",
    "3. Stream Cipher (LFSR)",
    "4. XOR Sederhana",
    "5. Super Enkripsi",
]

INFO = {
    MENUS[0]: ("Klasik · Substitusi",
               "Setiap huruf digeser sejauh *K* posisi di alfabet. `C = (P + K) mod 26`."),
    MENUS[1]: ("Klasik · Transposisi",
               "Plaintext ditulis zig-zag pada beberapa *rail* lalu dibaca per baris rail."),
    MENUS[2]: ("Modern · Cipher aliran (Materi 5)",
               "Keystream dibangkitkan oleh LFSR dari kunci bit, lalu di-XOR bit per bit: `Ci = Pi ⊕ Ki`."),
    MENUS[3]: ("Modern · XOR Sederhana (Materi 5)",
               "Plaintext di-XOR dengan kunci yang diulang secara periodik: `C = P ⊕ K`. "
               "Prinsipnya sama seperti Vigenère cipher, hanya dalam mode bit."),
    MENUS[4]: ("Super enkripsi",
               "Gabungan 4 algoritma: **Caesar → Rail Fence → Stream (LFSR) → XOR Sederhana**. "
               "Dekripsi dilakukan dengan urutan terbalik."),
}


# ---------------------------------------------------------------- tampilan proses
def render_steps(steps):
    for s in steps:
        st.markdown(f"**{s['title']}**")
        if s.get("desc"):
            st.markdown(s["desc"])
        if s.get("table"):
            st.dataframe(pd.DataFrame(s["table"]).astype(str), hide_index=True)
        if s.get("code"):
            st.code(s["code"], language=None)


def render_stages(stages):
    for name, inp, out, steps in stages:
        with st.expander(name, expanded=False):
            c1, c2 = st.columns(2)
            c1.markdown("**Input tahap ini**")
            c1.code(inp, language=None)
            c2.markdown("**Output tahap ini**")
            c2.code(out, language=None)
            render_steps(steps)


def run(fn, *args):
    try:
        return fn(*args)
    except ValueError as e:
        st.error(str(e))
        return None


def show_result(label, result, steps=None, stages=None):
    st.success(f"{label}:")
    st.code(result, language=None)
    st.subheader("Proses Algoritma")
    if stages is not None:
        st.caption("Klik tiap tahap untuk melihat prosesnya.")
        render_stages(stages)
    else:
        render_steps(steps)


# ---------------------------------------------------------------- halaman per menu
def page_simple(menu, enc_fn, dec_fn, key_widget, enc_input_label="Plaintext", dec_input_label="Ciphertext"):
    tab_e, tab_d = st.tabs(["🔒 Enkripsi", "🔓 Dekripsi"])
    with tab_e:
        text = st.text_area(enc_input_label, key=f"{menu}_pe", height=110)
        key = key_widget(f"{menu}_ke")
        if st.button("Enkripsi", key=f"{menu}_be", type="primary"):
            r = run(enc_fn, text, key)
            if r:
                show_result("Ciphertext", r[0], steps=r[1])
    with tab_d:
        text = st.text_area(dec_input_label, key=f"{menu}_pd", height=110)
        key = key_widget(f"{menu}_kd")
        if st.button("Dekripsi", key=f"{menu}_bd", type="primary"):
            r = run(dec_fn, text, key)
            if r:
                show_result("Plaintext", r[0], steps=r[1])


def caesar_key(k):
    return st.number_input("Kunci (jumlah geseran)", 0, 1000, 3, key=k)


def rail_key(k):
    return st.number_input("Jumlah rail", 2, 50, 3, key=k)


def seed_key(k):
    return st.text_input("Kunci LFSR (4–16 bit, bukan semua 0)", "1111", key=k)


def xor_key(k):
    return st.text_input("Kunci (teks, akan diulang periodik)", "kunci", key=k)


def page_super():
    def keys(p):
        c1, c2 = st.columns(2)
        shift = c1.number_input("Caesar: geseran", 0, 1000, 3, key=f"{p}_s")
        rails = c2.number_input("Rail Fence: jumlah rail", 2, 50, 3, key=f"{p}_r")
        seed = c1.text_input("LFSR: kunci bit", "1011", key=f"{p}_l")
        key = c2.text_input("XOR Sederhana: kunci teks", "kunci", key=f"{p}_b")
        return shift, rails, seed, key

    tab_e, tab_d = st.tabs(["🔒 Enkripsi", "🔓 Dekripsi"])
    with tab_e:
        text = st.text_area("Plaintext", key="sup_pe", height=110)
        k = keys("sup_e")
        if st.button("Enkripsi", key="sup_be", type="primary"):
            r = run(ca.super_encrypt, text, *k)
            if r:
                show_result("Ciphertext akhir (hex)", r[0], stages=r[1])
    with tab_d:
        text = st.text_area("Ciphertext (hex)", key="sup_pd", height=110)
        k = keys("sup_d")
        st.caption("Semua kunci harus sama dengan saat enkripsi.")
        if st.button("Dekripsi", key="sup_bd", type="primary"):
            r = run(ca.super_decrypt, text, *k)
            if r:
                show_result("Plaintext", r[0], stages=r[1])


# ---------------------------------------------------------------- main
st.sidebar.title("🔐 Aplikasi Kriptografi")
menu = st.sidebar.radio("Menu", MENUS)
st.sidebar.caption("Menu 1–2: klasik · Menu 3–4: modern · Menu 5: super enkripsi")

kind, desc = INFO[menu]
st.title(menu)
st.caption(kind)
st.markdown(desc)
st.divider()

if menu == MENUS[0]:
    page_simple(menu, ca.caesar_encrypt, ca.caesar_decrypt, caesar_key)
elif menu == MENUS[1]:
    page_simple(menu, ca.railfence_encrypt, ca.railfence_decrypt, rail_key)
elif menu == MENUS[2]:
    page_simple(menu, ca.stream_encrypt, ca.stream_decrypt, seed_key, dec_input_label="Ciphertext (hex)")
elif menu == MENUS[3]:
    page_simple(menu, ca.xor_encrypt, ca.xor_decrypt, xor_key, dec_input_label="Ciphertext (hex)")
else:
    page_super()