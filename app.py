import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import datetime
import pytz
import time
import streamlit.components.v1 as components
from utils import *
from streamlit_autorefresh import st_autorefresh

st.set_page_config(page_title="CTI WAR ROOM", layout="wide", page_icon="🛡️")

# CSS
st.markdown("""<style>
.stApp { background-color: #0b0f19; }
.report-card { background: rgba(30, 41, 59, 0.4); border: 1px solid rgba(148, 163, 184, 0.1); padding: 20px; margin-bottom: 15px; border-radius: 8px; }
.card-incd { border-right: 4px solid #3b82f6; }
.footer { text-align: center; color: #64748b; font-size: 0.8rem; margin-top: 50px; }
</style>""", unsafe_allow_html=True)

init_db()
IL_TZ = pytz.timezone('Asia/Jerusalem')
REFRESH_MINUTES = 15

# Keys
GROQ_KEY = st.secrets.get("groq_key", "")
VT_KEY = st.secrets.get("vt_key", "")
URLSCAN_KEY = st.secrets.get("urlscan_key", "")
ABUSE_KEY = st.secrets.get("abuseipdb_key", "")

# Auto Refresh
st_autorefresh(interval=REFRESH_MINUTES * 60 * 1000, key="data_refresh")

async def perform_update():
    col, proc = CTICollector(), AIBatchProcessor(GROQ_KEY)
    raw = await col.get_all_data() # This now includes automated DeepWeb scans
    if raw:
        analyzed = await proc.analyze_batch(raw)
        return save_reports(raw, analyzed)
    return 0

if "last_run" not in st.session_state:
    st.session_state["last_run"] = datetime.datetime.now(IL_TZ)
    asyncio.run(perform_update())
else:
    if (datetime.datetime.now(IL_TZ) - st.session_state["last_run"]).total_seconds() > (REFRESH_MINUTES * 60):
        asyncio.run(perform_update())
        st.session_state["last_run"] = datetime.datetime.now(IL_TZ)

st.title("OPERATIONAL DASHBOARD")
st.caption(f"Last Update: {st.session_state['last_run'].strftime('%H:%M')}")

tab_feed, tab_tools, tab_strat, tab_map = st.tabs(["🔴 LIVE FEED", "🛠️ INVESTIGATION LAB", "🧠 THREAT PROFILER", "🌍 HEATMAP"])

# --- TAB 1: LIVE FEED (No DeepWeb) ---
with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    # FILTER: Exclude DeepWeb from Live Feed
    df = pd.read_sql_query("SELECT * FROM intel_reports WHERE source != 'DeepWeb' AND published_at > datetime('now', '-2 days') ORDER BY published_at DESC LIMIT 50", conn)
    conn.close()
    
    for _, row in df.iterrows():
        st.markdown(f"""
        <div class="report-card {'card-incd' if row['source']=='INCD' else ''}">
            <small>{row['published_at']} | {row['source']}</small>
            <h3>{row['title']}</h3>
            <p>{row['summary']}</p>
            <a href="{row['url']}" target="_blank">OPEN REPORT</a>
        </div>
        """, unsafe_allow_html=True)

# --- TAB 2: INVESTIGATION ---
with tab_tools:
    ioc = st.text_input("Enter IOC")
    if st.button("SCAN") and ioc:
        # Standard Scan Logic
        tl = ThreatLookup(VT_KEY, URLSCAN_KEY, ABUSE_KEY)
        vt = tl.query_virustotal(ioc, identify_ioc_type(ioc))
        proc = AIBatchProcessor(GROQ_KEY)
        res = asyncio.run(proc.analyze_single_ioc(ioc, identify_ioc_type(ioc), {"virustotal": vt}))
        st.markdown(res)

# --- TAB 3: THREAT PROFILER (Auto History) ---
with tab_strat:
    actors = APTSheetCollector().fetch_threats()
    sel = st.selectbox("Select Actor", [a['name'] for a in actors])
    actor = next(a for a in actors if a['name'] == sel)
    
    # Show History (Including DeepWeb)
    conn = sqlite3.connect(DB_NAME)
    keys = actor['keywords'] + [actor['name']]
    q = f"SELECT * FROM intel_reports WHERE {' OR '.join([f'title LIKE \"%{k}%\"' for k in keys])} ORDER BY published_at DESC LIMIT 10"
    df = pd.read_sql_query(q, conn)
    conn.close()
    
    st.write(f"### Intelligence History: {actor['name']}")
    st.dataframe(df[['published_at', 'source', 'title']])

# --- TAB 4: MAP ---
with tab_map:
    components.iframe("https://threatmap.checkpoint.com/", height=600)
