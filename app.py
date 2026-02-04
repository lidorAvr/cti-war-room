import streamlit as st
import pandas as pd
import sqlite3
import time
import streamlit.components.v1 as components
from streamlit_autorefresh import st_autorefresh
from utils import *

st.set_page_config(page_title="SOC War Room", layout="wide", page_icon="🛡️")

st.markdown("""
<style>
    /* Dark Theme */
    .stApp { background-color: #0e1117; color: #fff; }
    .card { background: #262730; padding: 15px; border-radius: 10px; border-left: 5px solid #444; margin-bottom: 15px; }
    .card h4 { color: #fff; margin: 0; }
    .card p { color: #ccc; font-size: 0.9em; }
    .tag { padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8em; margin-right: 5px; }
    .tag-crit { background: #5a1a1a; color: #ffcccc; border: 1px solid #cc0000; }
    .tag-high { background: #5a4a1a; color: #ffffcc; border: 1px solid #806000; }
    .tag-il { background: #1a3a5a; color: #cce5ff; border: 1px solid #004080; }
</style>
""", unsafe_allow_html=True)

st_autorefresh(interval=15 * 60 * 1000, key="auto_refresh")
init_db()

# --- SECRETS DEBUGGER ---
try:
    GENAI_KEY = st.secrets.get("gemini_key", "")
    VT_KEY = st.secrets.get("vt_key", "")
    US_KEY = st.secrets.get("urlscan_key", "")
    AB_KEY = st.secrets.get("abuseipdb_key", "")
except:
    st.error("No secrets found!")
    st.stop()

st.title("🛡️ SOC War Room")

with st.sidebar:
    st.header("⚙️ Config Status")
    # בדיקה ויזואלית האם המפתחות נטענו
    st.markdown(f"**Gemini AI:** {'✅ Loaded' if GENAI_KEY else '❌ Missing'}")
    st.markdown(f"**VirusTotal:** {'✅ Loaded' if VT_KEY else '⚠️ Optional'}")
    st.markdown(f"**URLScan:** {'✅ Loaded' if US_KEY else '⚠️ Optional'}")
    
    st.divider()
    if st.button("🚀 Force Global Scan", type="primary"):
        with st.spinner("Analyzing Feeds (Gov.il, Calcalist, Global)..."):
            col = CTICollector()
            ai = AIHandler(GENAI_KEY)
            raw = col.fetch_all()
            analyzed = ai.analyze_batch(raw)
            cnt = save_reports(raw, analyzed)
            st.success(f"Added {cnt} reports")
            time.sleep(1)
            st.rerun()

# --- TABS ---
tab1, tab2, tab3, tab4 = st.tabs(["🔴 Feed", "🛠️ Toolbox", "🧠 Strategic", "🌍 Map"])

with tab1:
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql("SELECT * FROM intel_reports ORDER BY id DESC LIMIT 50", conn)
    conn.close()
    
    col1, col2, col3, col4 = st.columns(4)
    if col1.button("🚨 Critical"): st.session_state.filt = 'Critical'
    if col2.button("🇮🇱 Israel"): st.session_state.filt = 'Israel'
    if col4.button("🌐 All"): st.session_state.filt = 'All'
    
    filt = st.session_state.get('filt', 'All')
    
    if not df.empty:
        for _, row in df.iterrows():
            if filt == 'Critical' and 'Critical' not in row['severity']: continue
            if filt == 'Israel' and 'Israel' not in row['category']: continue
            
            sev_cls = "tag-crit" if "Critical" in row['severity'] else "tag-high"
            il_cls = "tag-il" if "Israel" in row['category'] else ""
            
            st.markdown(f"""
            <div class="card">
                <div>
                    <span class="tag {sev_cls}">{row['severity']}</span>
                    <span class="tag {il_cls}">{row['category']}</span>
                    <small style="color:#888; float:right">{row['published_at'][:16]}</small>
                </div>
                <h4>{row['title']}</h4>
                <p>{row['summary']}</p>
                <div style="margin-top:10px">
                    <span style="color:#aaa; font-size:0.8em">{row['source']}</span> | 
                    <a href="{row['url']}" target="_blank">Read Source</a>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No reports. Click 'Force Global Scan' in the sidebar.")

with tab2:
    ioc = st.text_input("Investigate IOC")
    if st.button("Check"):
        tl = ThreatLookup(VT_KEY, US_KEY, AB_KEY)
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("### VirusTotal")
            st.write(tl.check_vt(ioc))
        with c2:
            st.markdown("### URLScan")
            res = tl.check_urlscan(ioc)
            if res['status'] == 'found':
                if res.get('screenshot'): st.image(res['screenshot'])
                st.write(f"Verdict: {res.get('verdict')}")
            else: st.write(res)

with tab3:
    st.subheader("APT Hunting & Detection")
    actors = APTData.get_actors()
    cols = st.columns(3)
    for i, a in enumerate(actors):
        with cols[i%3]:
            with st.container(border=True):
                st.markdown(f"**{a['origin']} {a['name']}**")
                st.caption(a['tools'])
                if st.button(f"Generate Rules", key=f"btn_{i}"):
                    ai = AIHandler(GENAI_KEY)
                    with st.spinner("Generating YARA-L & XQL..."):
                        st.markdown(ai.generate_hunting(a))

with tab4:
    st.subheader("Global Threat Map")
    components.iframe("https://threatmap.checkpoint.com/", height=600)
