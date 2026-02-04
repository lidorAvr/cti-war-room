import streamlit as st
import pandas as pd
import sqlite3
import time
import streamlit.components.v1 as components
from streamlit_autorefresh import st_autorefresh
from utils import *

st.set_page_config(page_title="SOC War Room", layout="wide", page_icon="🛡️")

# --- CUSTOM CSS (Clean White Theme) ---
st.markdown("""
<style>
    .card {
        background-color: #ffffff;
        padding: 20px;
        border-radius: 10px;
        border-left: 6px solid #444;
        margin-bottom: 15px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        color: #222;
    }
    .card h4 { margin: 0 0 10px 0; color: #000; font-size: 1.2rem; }
    .card p { color: #444; font-size: 0.95rem; margin-bottom: 5px; }
    .meta { font-size: 0.85rem; color: #666; display: flex; justify-content: space-between; }
    
    .tag { padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8rem; margin-right: 5px; }
    .tag-critical { background: #ffe6e6; color: #cc0000; border: 1px solid #cc0000; }
    .tag-high { background: #fff8e1; color: #f57f17; border: 1px solid #f57f17; }
    .tag-il { background: #e3f2fd; color: #0d47a1; border: 1px solid #0d47a1; }
    
    .status-box { background: #f8f9fa; padding: 10px; border-radius: 8px; border: 1px solid #ddd; color: #333; margin-bottom: 20px; }
</style>
""", unsafe_allow_html=True)

# Auto Refresh (15 min)
st_autorefresh(interval=15 * 60 * 1000, key="auto_refresh")

# Initialize DB (This is the ONLY place it should be called)
init_db()

# --- LOAD SECRETS ---
try:
    GENAI_KEY = st.secrets["gemini_key"]
    VT_KEY = st.secrets.get("vt_key", "")
    US_KEY = st.secrets.get("urlscan_key", "")
    AB_KEY = st.secrets.get("abuseipdb_key", "")
except:
    st.error("❌ Critical: secrets.toml not found or missing keys!")
    st.stop()

# --- SIDEBAR ---
with st.sidebar:
    st.header("⚙️ Controls")
    
    if st.button("🚀 Force Global Update", type="primary"):
        with st.spinner("Scanning INCD, Calcalist, & RSS Feeds..."):
            col = CTICollector()
            ai = AIHandler(GENAI_KEY)
            
            raw = col.fetch_all()
            analyzed = ai.analyze_batch(raw)
            cnt = save_reports(raw, analyzed)
            
            st.success(f"Done! {cnt} new items added.")
            time.sleep(1)
            st.rerun()
            
    st.info(f"API Status:\n- Gemini: {'✅' if GENAI_KEY else '❌'}\n- VirusTotal: {'✅' if VT_KEY else '❌'}")

# --- MAIN LAYOUT ---
st.title("🛡️ SOC War Room")
st.markdown(f"<div class='status-box'>📡 <b>System Status:</b> Online | 🕒 <b>Last Check:</b> {datetime.datetime.now(IL_TZ).strftime('%H:%M')}</div>", unsafe_allow_html=True)

tab_feed, tab_tools, tab_strat, tab_map = st.tabs(["🔴 Live Feed", "🛠️ Toolbox", "🧠 Strategic", "🌍 Map"])

# --- TAB 1: FEED ---
with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql("SELECT * FROM intel_reports ORDER BY id DESC", conn)
    conn.close()
    
    # Filter Buttons
    c1, c2, c3, c4 = st.columns(4)
    cnt_crit = len(df[df['severity'].str.contains('Critical', case=False)]) if not df.empty else 0
    cnt_il = len(df[df['category'].str.contains('Israel', case=False)]) if not df.empty else 0
    
    if c1.button(f"🚨 Critical ({cnt_crit})"): st.session_state.filt = 'Critical'
    if c2.button(f"🇮🇱 Israel ({cnt_il})"): st.session_state.filt = 'Israel'
    if c4.button("🌐 Show All"): st.session_state.filt = 'All'
    
    filt = st.session_state.get('filt', 'All')
    
    if not df.empty:
        for _, row in df.iterrows():
            if filt == 'Critical' and 'Critical' not in row['severity']: continue
            if filt == 'Israel' and 'Israel' not in row['category']: continue
            
            sev = row['severity']
            color_class = "tag-critical" if "Critical" in sev else ("tag-high" if "High" in sev else "")
            il_class = "tag-il" if "Israel" in row['category'] else ""
            
            st.markdown(f"""
            <div class="card">
                <div>
                    <span class="tag {color_class}">{sev}</span>
                    <span class="tag {il_class}">{row['category']}</span>
                </div>
                <h4>{row['title']}</h4>
                <p>{row['summary']}</p>
                <div class="meta">
                    <span>{row['source']} | {row['published_at'][:16]}</span>
                    <a href="{row['url']}" target="_blank">Read Source ↗</a>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No reports found. Click 'Force Global Update'.")

# --- TAB 2: TOOLBOX ---
with tab_tools:
    ioc = st.text_input("Investigate IOC (IP/Domain)")
    if st.button("🔍 Scan"):
        if ioc:
            tl = ThreatLookup(VT_KEY, US_KEY, AB_KEY)
            
            c1, c2 = st.columns(2)
            with c1: 
                st.subheader("VirusTotal")
                res = tl.check_vt(ioc)
                if res['status'] == 'found': st.json(res['data'])
                else: st.warning(f"VT: {res['status']}")
            
            with c2:
                st.subheader("URLScan")
                res = tl.check_urlscan(ioc)
                if res['status'] == 'found':
                    st.write(f"**Verdict:** {res['verdict']}")
                    if res['screenshot']: st.image(res['screenshot'])
                else: st.warning(f"URLScan: {res['status']}")

# --- TAB 3: STRATEGIC ---
with tab_strat:
    st.subheader("Active Threat Groups (Israel/ME)")
    
    conn = sqlite3.connect(DB_NAME)
    all_text = pd.read_sql("SELECT title FROM intel_reports", conn).to_string().lower()
    conn.close()
    
    actors = APTData.get_actors()
    cols = st.columns(3)
    
    for i, actor in enumerate(actors):
        is_active = actor['name'].lower() in all_text
        with cols[i%3]:
            with st.container(border=True):
                status = "🔴 ACTIVE IN NEWS" if is_active else "⚪ Monitoring"
                st.markdown(f"**{actor['origin']} {actor['name']}**")
                st.caption(status)
                st.markdown(f"**Tools:** `{actor['tools']}`")
                
                if st.button(f"🏹 Hunt {actor['name']}", key=f"h_{i}"):
                    ai = AIHandler(GENAI_KEY)
                    with st.spinner("Generating Queries (Chronicle/XDR)..."):
                        st.markdown(ai.generate_hunting(actor))

# --- TAB 4: MAP ---
with tab_map:
    st.subheader("Live Threat Map")
    components.iframe("https://threatmap.checkpoint.com/", height=600, scrolling=False)
