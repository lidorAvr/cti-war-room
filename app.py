import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import datetime
import pytz
import time
from utils import *
from streamlit_autorefresh import st_autorefresh

st.set_page_config(page_title="CTI WAR ROOM", layout="wide", page_icon="🛡️")

# --- CSS STYLING --- (Same as original)
st.markdown("""<style>...</style>""", unsafe_allow_html=True) # שמרתי על ה-CSS המקורי שלך

# --- CORE LOGIC ---
init_db()
IL_TZ = pytz.timezone('Asia/Jerusalem')
st_autorefresh(interval=15 * 60 * 1000, key="data_refresh")

GROQ_KEY = st.secrets.get("groq_key", "")
VT_KEY = st.secrets.get("vt_key", "")
URLSCAN_KEY = st.secrets.get("urlscan_key", "")
ABUSE_KEY = st.secrets.get("abuseipdb_key", "")

async def perform_smart_update(status_ui):
    col, proc = CTICollector(), AIBatchProcessor(GROQ_KEY)
    status_ui.update(label="📡 אוסף ידיעות ממקורות...", state="running")
    raw = await col.get_all_data()
    
    # FILTER: Analyze only new URLs
    processed_urls = get_processed_urls_set()
    new_items = [item for item in raw if item['url'] not in processed_urls]
    
    if new_items:
        status_ui.update(label=f"🤖 מנתח {len(new_items)} ידיעות חדשות ב-AI...", state="running")
        analyzed = await proc.analyze_batch(new_items)
        return save_reports(new_items, analyzed)
    return 0

async def perform_actor_scan(status_ui):
    threats = APTSheetCollector().fetch_threats()
    scanner, proc = DeepWebScanner(), AIBatchProcessor(GROQ_KEY)
    processed_urls = get_processed_urls_set()
    
    status_ui.update(label="🕵️ סורק Deep Web עבור APTs...", state="running")
    fetch_tasks = [asyncio.to_thread(scanner.scan_actor, t['name'], 2) for t in threats]
    all_results = await asyncio.gather(*fetch_tasks)
    
    combined_new = []
    for res in all_results:
        if res: combined_new.extend([r for r in res if r['url'] not in processed_urls])
        
    if combined_new:
        status_ui.update(label=f"🧠 מעבד {len(combined_new)} ממצאי Deep Web...", state="running")
        analyzed = await proc.analyze_batch(combined_new)
        save_reports(combined_new, analyzed)

# --- BOOT SEQUENCE ---
if "booted" not in st.session_state:
    with st.status("🚀 מתניע מערכת מודיעין...", expanded=True) as status:
        p_bar = st.progress(0)
        
        status.write("🔍 בודק תקינות בסיס נתונים...")
        init_db()
        p_bar.progress(20)
        
        # Step 1: News Update
        asyncio.run(perform_smart_update(status))
        p_bar.progress(60)
        
        # Step 2: Actor Update
        asyncio.run(perform_actor_scan(status))
        p_bar.progress(95)
        
        status.update(label="✅ מערכת מבצעית מוכנה!", state="complete", expanded=False)
        p_bar.progress(100)
        time.sleep(1)
        
    st.session_state['booted'] = True
    st.rerun()

# --- SIDEBAR & UI --- (Keep original from here down)
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/9203/9203726.png", width=60)
    st.markdown("### CTI WAR ROOM")
    ok, msg = ConnectionManager.check_groq(GROQ_KEY)
    st.caption(f"AI STATUS: {msg}")
    if st.button("⚡ סנכרון ידני"):
        with st.status("מסנכרן...") as s:
            asyncio.run(perform_smart_update(s))
        st.rerun()

st.title("לוח בקרה מבצעי")
# ... שאר הקוד המקורי שלך (Metrics, Tabs וכו') ממשיך מכאן בדיוק כפי שהיה ...
