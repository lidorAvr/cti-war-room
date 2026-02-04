import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import base64
import json
from streamlit_autorefresh import st_autorefresh
# התיקון: הפרדת השורות
from utils import * st.set_page_config(page_title="SOC War Room", layout="wide", page_icon="🛡️")

st.markdown("""
<style>
    .report-card { background-color: #1E1E1E; padding: 15px; border-radius: 8px; border: 1px solid #333; margin-bottom: 10px; }
    .tag { padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; margin-right: 5px; }
    .tag-critical { background-color: #721c24; color: #f8d7da; }
    .tag-high { background-color: #856404; color: #fff3cd; }
    .tag-israel { background-color: #004085; color: #cce5ff; }
    .tag-medium { background-color: #0c5460; color: #d1ecf1; }
</style>
""", unsafe_allow_html=True)

st_autorefresh(interval=15 * 60 * 1000, key="auto_refresh")
init_db()

if 'filter_type' not in st.session_state: st.session_state.filter_type = 'All'

st.title("🛡️ SOC War Room")

# --- SIDEBAR: KEY DEBUGGING ---
with st.sidebar:
    st.header("🔧 API Configuration")
    
    # טעינת מפתח: קודם מ-Secrets, אם אין - אז מהתיבה הידנית
    try: 
        secret_key = st.secrets["gemini_key"]
    except: 
        secret_key = ""
    
    # תיבת טקסט למפתח - זה הפתרון הכי בטוח כרגע
    user_key = st.text_input("Gemini API Key:", value=secret_key, type="password")
    
    # המפתח בפועל לשימוש
    gemini_key = user_key

    if st.button("🧪 Test Connection"):
        if gemini_key:
            with st.spinner("Connecting to Google..."):
                ok, msg = ConnectionManager.check_gemini(gemini_key)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)
        else:
            st.warning("Please enter a key first.")

    st.divider()
    
    if st.button("🚀 Run Scan"):
        with st.spinner("Analyzing..."):
            async def scan():
                # אתחול האובייקטים עם המפתח שהוזן
                col = CTICollector()
                # חשוב: מעבירים את המפתח ל-Processor
                proc = AIBatchProcessor(gemini_key)
                
                raw = await col.get_all_data()
                analyzed = await proc.analyze_batch(raw)
                return save_reports(raw, analyzed)
            
            c = asyncio.run(scan())
            st.success(f"Scan Logic Finished. Items processed: {c}")
            st.rerun()

# --- TABS ---
tab1, tab2 = st.tabs(["Feed", "Tools"])

with tab1:
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM intel_reports ORDER BY published_at DESC", conn)
    conn.close()
    
    if df.empty:
        st.info("No reports yet. Click 'Run Scan' in the sidebar.")
    else:
        for _, row in df.iterrows():
            st.markdown(f"""
            <div class="report-card">
                <h4>{row['title']}</h4>
                <p>{row['summary']}</p>
                <small>Source: {row['source']} | Severity: {row['severity']}</small>
                <br><a href="{row['url']}" target="_blank">Read More</a>
            </div>""", unsafe_allow_html=True)

with tab2:
    ioc = st.text_input("Check IOC (e.g., 1.1.1.1)")
    if st.button("Analyze IOC"):
        if gemini_key:
            proc = AIBatchProcessor(gemini_key)
            with st.spinner("Asking AI..."):
                res = asyncio.run(proc.analyze_single_ioc(ioc, {"raw": "data"}))
                st.markdown(res)
        else:
            st.error("Enter API Key first.")
