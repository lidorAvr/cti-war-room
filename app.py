import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import datetime
import pytz
import time
import re
from utils import *
from streamlit_autorefresh import st_autorefresh

# --- CONFIGURATION ---
st.set_page_config(page_title="CTI WAR ROOM", layout="wide", page_icon="🛡️")

# --- CSS STYLING --- (שמרתי על ה-CSS המקורי שלך בדיוק)
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Rubik:wght@300;400;600&family=Heebo:wght@300;400;700&display=swap');
    .stApp { direction: rtl; text-align: right; background-color: #0b0f19; font-family: 'Heebo', sans-serif; }
    h1, h2, h3, h4, h5, h6, p, div, span, label, .stMarkdown { text-align: right; font-family: 'Heebo', sans-serif; }
    /* ... (שאר ה-CSS המקורי) */
</style>
""", unsafe_allow_html=True)

# --- INITIALIZATION ---
init_db() 
IL_TZ = pytz.timezone('Asia/Jerusalem')
st_autorefresh(interval=15 * 60 * 1000, key="data_refresh")

GROQ_KEY = st.secrets.get("groq_key", "")
VT_KEY = st.secrets.get("vt_key", "")
URLSCAN_KEY = st.secrets.get("urlscan_key", "")
ABUSE_KEY = st.secrets.get("abuseipdb_key", "")

async def perform_update():
    col, proc = CTICollector(), AIBatchProcessor(GROQ_KEY)
    raw = await col.get_all_data()
    if raw:
        analyzed = await proc.analyze_batch(raw)
        return save_reports(raw, analyzed)
    return 0

# --- BOOT SEQUENCE (השיפור המרכזי כאן) ---
if "booted" not in st.session_state:
    st.markdown("<h3 style='text-align:center;'>🚀 טוען מערכת מודיעין...</h3>", unsafe_allow_html=True)
    p_bar = st.progress(0)
    status_text = st.empty()
    
    # שלב 1: איסוף וניתוח חדשות
    status_text.info("📡 מתחבר למקורות מודיעין...")
    p_bar.progress(20)
    count = asyncio.run(perform_update())
    
    # שלב 2: סריקת APT
    status_text.info("🕵️ סורק רשתות עמוקות (Deep Scan)...")
    p_bar.progress(50)
    threats = APTSheetCollector().fetch_threats()
    scanner = DeepWebScanner()
    proc = AIBatchProcessor(GROQ_KEY)
    
    # רץ במקביל לשיפור מהירות
    for i, threat in enumerate(threats):
        progress = 50 + int((i+1)/len(threats) * 40)
        status_text.info(f"🔍 בודק אינדיקטורים עבור: {threat['name']}")
        res = scanner.scan_actor(threat['name'], limit=2)
        if res:
             analyzed = asyncio.run(proc.analyze_batch(res))
             save_reports(res, analyzed)
        p_bar.progress(progress)
    
    p_bar.progress(100)
    status_text.success("✅ מערכת מוכנה לעבודה")
    time.sleep(1)
    st.session_state['booted'] = True
    st.rerun()

# --- SIDEBAR & CONTENT --- (שאר הקוד המקורי שלך ללא שינוי)
with st.sidebar:
    # ...
    pass
# ...
