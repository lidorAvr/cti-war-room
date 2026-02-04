import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import base64
import json
import streamlit.components.v1 as components
from streamlit_autorefresh import st_autorefresh
from utils import * # Import everything safely now

st.set_page_config(page_title="SOC War Room", layout="wide", page_icon="🛡️")

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

# --- SIDEBAR & KEY MANAGEMENT ---
with st.sidebar:
    st.header("⚙️ Config")
    
    # 1. Try to load from secrets
    try:
        secret_key = st.secrets["gemini_key"]
        st.success("🔑 Gemini Key loaded from Secrets")
    except:
        secret_key = ""
        st.warning("⚠️ No Secret found")

    # 2. Allow manual override
    user_key = st.text_input("Enter Gemini API Key (Manual Override)", value=secret_key, type="password")
    
    # Use the manual key if provided, otherwise secret
    gemini_key = user_key if user_key else secret_key

    if st.button("Test Connection"):
        ok, msg = ConnectionManager.check_gemini(gemini_key)
        if ok: st.success(msg)
        else: st.error(msg)

    st.divider()
    
    if st.button("🚀 Run Scan"):
        with st.spinner("Scanning..."):
            async def scan():
                col, proc = CTICollector(), AIBatchProcessor(gemini_key)
                raw = await col.get_all_data()
                analyzed = await proc.analyze_batch(raw)
                return save_reports(raw, analyzed)
            
            c = asyncio.run(scan())
            st.success(f"Done. {c} items.")
            st.rerun()

# --- TABS ---
tab_feed, tab_tools = st.tabs(["🔴 Live Feed", "🛠️ SOC Toolbox"])

with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM intel_reports ORDER BY published_at DESC", conn)
    conn.close()
    
    cols = st.columns(4)
    if cols[0].button("🚨 Critical"): st.session_state.filter_type = 'Critical'
    if cols[1].button("🇮🇱 Israel"): st.session_state.filter_type = 'Israel'
    if cols[3].button("All"): st.session_state.filter_type = 'All'

    view_df = df
    if st.session_state.filter_type == 'Critical': view_df = df[df['severity'] == 'Critical']
    elif st.session_state.filter_type == 'Israel': view_df = df[df['category'] == 'Israel Focus']

    if view_df.empty: st.info("No reports.")
    else:
        for _, row in view_df.iterrows():
            sev = "tag-critical" if row['severity']=='Critical' else "tag-medium"
            st.markdown(f"""
            <div class="report-card">
                <span class="tag {sev}">{row['severity']}</span>
                <span class="tag tag-medium">{row['category']}</span>
                <h4>{row['title']}</h4>
                <p>{row['summary']}</p>
                <a href="{row['url']}" target="_blank">Read More</a>
            </div>""", unsafe_allow_html=True)

with tab_tools:
    ioc = st.text_input("Investigate IOC")
    if st.button("Check"):
        st.info("Analyzing...")
        # Simple analysis
        proc = AIBatchProcessor(gemini_key)
        res = asyncio.run(proc.analyze_single_ioc(ioc, {"type": get_ioc_type(ioc)}))
        st.markdown(res)
