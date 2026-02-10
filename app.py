import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import datetime
import pytz
import time
from utils import *
from streamlit_autorefresh import st_autorefresh

# --- CONFIGURATION ---
st.set_page_config(page_title="CTI WAR ROOM", layout="wide", page_icon="🛡️")

# --- CSS STYLING (שמרתי על הסטייל המקורי שלך) ---
st.markdown("""<style>...</style>""", unsafe_allow_html=True) # השאר את ה-CSS שלך כאן

# --- INITIALIZATION ---
init_db() 
IL_TZ = pytz.timezone('Asia/Jerusalem')
st_autorefresh(interval=15 * 60 * 1000, key="data_refresh")

GROQ_KEY = st.secrets.get("groq_key", "")
VT_KEY = st.secrets.get("vt_key", "")
URLSCAN_KEY = st.secrets.get("urlscan_key", "")
ABUSE_KEY = st.secrets.get("abuseipdb_key", "")

# --- CORE UPDATE FUNCTIONS ---
async def update_live_feed(p_bar, status_text):
    status_text.info("📡 אוסף ידיעות חמות מהמקורות...")
    col, proc = CTICollector(), AIBatchProcessor(GROQ_KEY)
    raw = await col.get_all_data()
    p_bar.progress(30)
    if raw:
        status_text.info("🤖 מנתח מידע חדש (AI Processing)...")
        analyzed = await proc.analyze_batch(raw)
        save_reports(raw, analyzed)
    p_bar.progress(60)

async def update_threat_dossiers(p_bar, status_text):
    status_text.info("🕵️ מעדכן תיקי שחקני איום (Deep Scan)...")
    threats = APTSheetCollector().fetch_threats()
    scanner, proc = DeepWebScanner(), AIBatchProcessor(GROQ_KEY)
    for i, threat in enumerate(threats):
        res = scanner.scan_actor(threat['name'], limit=2)
        if res:
             analyzed = await proc.analyze_batch(res)
             save_reports(res, analyzed)
        p_bar.progress(60 + int((i+1)/len(threats) * 40))

# --- BOOT SEQUENCE (LAZY LOADING) ---
if "booted" not in st.session_state:
    st.markdown("<h3 style='text-align:center;'>🛡️ מאתחל חמ\"ל מודיעין...</h3>", unsafe_allow_html=True)
    p_bar = st.progress(0)
    status_text = st.empty()
    
    # שלב 1: טעינת ה-Feed המרכזי (חובה)
    asyncio.run(update_live_feed(p_bar, status_text))
    
    # שלב 2: סיום טעינה ראשונית - פותח את הממשק מיד!
    p_bar.progress(100)
    status_text.success("✅ עדכונים שוטפים מוכנים!")
    time.sleep(1)
    st.session_state['booted'] = True
    st.rerun()

# --- SIDEBAR & DASHBOARD ---
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/9203/9203726.png", width=60)
    st.markdown("### CTI WAR ROOM")
    ok, msg = ConnectionManager.check_groq(GROQ_KEY)
    st.caption(f"AI STATUS: {msg}")
    if st.button("⚡ סנכרון מלא"):
        with st.status("סנכרון עומק בתהליך...") as s:
            asyncio.run(update_live_feed(st.progress(0), st.empty()))
            asyncio.run(update_threat_dossiers(st.progress(0), st.empty()))
        st.rerun()

st.title("לוח בקרה מבצעי")
# ... (המשך המטריקות והטאבים שלך - ללא שינוי)
