import pandas as pd
import streamlit as st
import caesarChiper as cc
import railfenceChiper as rf
import streamChiperLFSR as sc

st.set_page_config(page_title="Aplikasi Kriptografi", page_icon="🔐", layout="wide")

MENUS = [
    "1. Caesar Cipher",
    "2. Rail Fence Cipher",
    "3. Stream Cipher (LFSR)",
    "4. Block Cipher (Feistel)",
    "5. Super Enkripsi",
]

INFO = {
    MENUS[0]: ("Klasik · Substitusi",
               "Setiap huruf digeser sejauh *K* posisi di alfabet. `C = (P + K) mod 26`."),
    MENUS[1]: ("Klasik · Transposisi",
               "Plaintext ditulis zig-zag pada beberapa *rail* lalu dibaca per baris rail."),
    MENUS[2]: ("Modern · Cipher aliran (Materi 5)",
               "Keystream dibangkitkan oleh LFSR dari kunci bit, lalu di-XOR bit per bit: `Ci = Pi ⊕ Ki`."),
    MENUS[3]: ("Modern · Cipher blok (Materi 5)",
               "Plaintext dibagi blok 64 bit dan diproses jaringan Feistel 8 putaran dengan kunci 64 bit. Blok terakhir diberi padding."),
    MENUS[4]: ("Super enkripsi",
               "Gabungan 4 algoritma: **Caesar → Rail Fence → Stream (LFSR) → Block (Feistel)**. Dekripsi dilakukan dengan urutan terbalik."),
}

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
    return st.text_input("Kunci LFSR (Hanya 4 atau 5 bit, bukan semua 0)", "1111", key=k)

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
    page_simple(menu, cc.enkripsi_caesar, cc.caesar_decrypt, caesar_key)
elif menu == MENUS[1]:
    page_simple(menu, rf.enkripsi_rail_fence, rf.dekripsi_rail_fence, rail_key)
elif menu == MENUS[2]:
    page_simple(menu, sc.stream_encrypt, sc.stream_decrypt, seed_key, dec_input_label="Ciphertext (hex)")
else:
    st.info("Menu algoritma ini belum disambungkan pada kode ini.")