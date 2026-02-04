import streamlit as st
import pandas as pd
import sqlite3
import time
import streamlit.components.v1 as components
from streamlit_autorefresh import st_autorefresh
from utils import *

st.set_page_config(page_title="SOC War Room", layout="wide", page_icon="🛡️")

# --- RICH UI STYLING (THE GOOD VERSION) ---
st.markdown("""
<style>
    /* Dark Mode Theme */
    .stApp { background-color: #0e1117; color: #fff; }
    
    /* Report Cards */
    .report-card {
        background-color: #262730;
        padding: 20px;
        border-radius: 12px;
        border: 1px solid #333;
        margin-bottom: 15px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
    .report-card:hover { border-color: #666; transform: translateY(-2px); transition: 0.2s; }
    
    /* Tags */
    .tag { padding: 4px 10px; border-radius: 6px; font-weight: bold; font-size: 0.8rem; margin-right: 8px; }
    .tag-crit { background: #5a1a1a; color: #ffcccc; border: 1px solid #800000; }
    .tag-high { background: #5a4a1a; color: #ffffcc; border: 1px solid #806000; }
    .tag-il { background: #1a3a5a; color: #cce5ff; border: 1px solid #004080; }
    
    /* Headers & Text */
    h4 { color: #fff; margin: 10px 0; }
    p { color: #ccc; }
    a { color: #4da6ff; text-decoration: none; }
    
    /* Strategic Cards */
    .strat-card { background: #1e1e1e; border-left: 5px solid #007acc; padding: 15px; margin-bottom: 10px; }
</style>
""", unsafe_allow_html=True)

st_autorefresh(interval=15 * 60 * 1000, key="auto_refresh")
init_db()

# --- KEYS ---
try:
    GENAI_KEY = st.secrets["gemini_key"]
    VT_KEY = st.secrets.get("vt_key", "")
    US_KEY = st.secrets.get("urlscan_key", "")
    AB_KEY = st.secrets.get("abuseipdb_key", "")
except:
    st.error("Secrets Error. Check config.")
    st.stop()

st.title("🛡️ SOC War Room")
st.caption("Advanced Threat Intelligence & Hunting Platform")

# --- SIDEBAR ---
with st.sidebar:
    st.header("⚙️ Operations")
    if st.button("🚀 Run Global Scan", type="primary"):
        with st.spinner("Scanning Sources (IL + Global)..."):
            col = CTICollector()
            ai = AIHandler(GENAI_KEY)
            raw = col.fetch_all()
            analyzed = ai.analyze_batch(raw)
            cnt = save_reports(raw, analyzed)
            st.success(f"Added {cnt} new reports!")
            time.sleep(1)
            st.rerun()
            
    st.divider()
    st.info(f"AI Status: {'✅ Connected' if GENAI_KEY else '❌'}")

# --- TABS ---
tab_feed, tab_tools, tab_strat, tab_map = st.tabs(["🔴 Live Feed", "🛠️ Toolbox", "🧠 Strategic", "🌍 Map"])

# --- FEED ---
with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql("SELECT * FROM intel_reports ORDER BY id DESC", conn)
    conn.close()
    
    c1, c2, c3, c4 = st.columns(4)
    if c1.button("🚨 Critical Only"): st.session_state.filt = 'Critical'
    if c2.button("🇮🇱 Israel Focus"): st.session_state.filt = 'Israel'
    if c4.button("🌐 Show All"): st.session_state.filt = 'All'
    
    filt = st.session_state.get('filt', 'All')
    
    if not df.empty:
        for _, row in df.iterrows():
            if filt == 'Critical' and 'Critical' not in row['severity']: continue
            if filt == 'Israel' and 'Israel' not in row['category']: continue
            
            sev_cls = "tag-crit" if "Critical" in row['severity'] else "tag-high"
            il_cls = "tag-il" if "Israel" in row['category'] else ""
            
            st.markdown(f"""
            <div class="report-card">
                <div>
                    <span class="tag {sev_cls}">{row['severity']}</span>
                    <span class="tag {il_cls}">{row['category']}</span>
                    <small style="color:#888; float:right">{row['published_at'][:16]}</small>
                </div>
                <h4>{row['title']}</h4>
                <p>{row['summary']}</p>
                <div style="margin-top:10px; font-size:0.9rem">
                    <span style="color:#aaa">Src: {row['source']}</span> | 
                    <a href="{row['url']}" target="_blank">Read More ↗</a>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("Feed empty. Run a scan from the sidebar.")

# --- TOOLBOX ---
with tab_tools:
    ioc = st.text_input("Enter IOC (IP/Domain/Hash)")
    if st.button("🔍 Investigate IOC"):
        tl = ThreatLookup(VT_KEY, US_KEY, AB_KEY)
        
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("### VirusTotal")
            res = tl.check_vt(ioc)
            if res['status'] == 'found': st.success(res['data'])
            else: st.warning(res['status'])
            
        with c2:
            st.markdown("### URLScan.io")
            res = tl.check_urlscan(ioc)
            if res['status'] == 'found':
                d = res['data']
                st.write(f"**Verdict:** {d.get('verdict', {}).get('overall', 'N/A')}")
                if d.get('screenshot'): st.image(d['screenshot'])
            else: st.warning(res['status'])
            
        st.divider()
        if st.button("✨ Ask AI Analyst"):
            ai = AIHandler(GENAI_KEY)
            with st.spinner("AI Analyzing..."):
                st.markdown(ai.generate_hunting({"name": "IOC Investigation", "tools": ioc}))

# --- STRATEGIC ---
with tab_strat:
    st.subheader("Active Threat Groups (Israel/ME)")
    actors = APTData.get_actors()
    
    cols = st.columns(3)
    for i, actor in enumerate(actors):
        with cols[i%3]:
            with st.container():
                st.markdown(f"""
                <div class="strat-card">
                    <h3>{actor['origin']} {actor['name']}</h3>
                    <p><b>Target:</b> {actor['target']}</p>
                    <p><b>Tools:</b> {actor['tools']}</p>
                </div>
                """, unsafe_allow_html=True)
                
                if st.button(f"🏹 Hunt {actor['name']}", key=f"h_{i}"):
                    ai = AIHandler(GENAI_KEY)
                    with st.spinner("Generating Detection Rules (Chronicle/XDR)..."):
                        st.markdown(ai.generate_hunting(actor))

# --- MAP ---
with tab_map:
    st.subheader("Live Cyber Attack Map")
    components.iframe("https://threatmap.checkpoint.com/", height=700, scrolling=False)
