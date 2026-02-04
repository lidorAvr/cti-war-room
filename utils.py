import streamlit as st
import pandas as pd
import sqlite3
import time
from streamlit_autorefresh import st_autorefresh
from utils import *

st.set_page_config(page_title="SOC War Room", layout="wide", page_icon="🛡️")

# CSS for Dark Mode Support
st.markdown("""<style>
.card { background-color: #262730; padding: 15px; border-radius: 10px; margin-bottom: 10px; border-left: 5px solid #555; }
.card h4 { margin: 0; color: #fff; }
.card p { color: #ccc; font-size: 0.9em; }
.tag { padding: 3px 8px; border-radius: 4px; font-weight: bold; font-size: 0.8em; margin-right: 5px; }
.critical { background-color: #8B0000; color: #fff; }
.high { background-color: #B8860B; color: #fff; }
</style>""", unsafe_allow_html=True)

# Auto Refresh every 15 min
st_autorefresh(interval=15 * 60 * 1000, key="auto_refresh")
init_db()

# Secrets
try:
    GENAI_KEY = st.secrets["gemini_key"]
    configure_ai(GENAI_KEY)
except:
    st.error("Missing 'gemini_key' in secrets.toml")
    st.stop()

VT_KEY = st.secrets.get("vt_key", "")
US_KEY = st.secrets.get("urlscan_key", "")
AB_KEY = st.secrets.get("abuseipdb_key", "")

# Layout
st.title("🛡️ SOC War Room")
tab1, tab2, tab3 = st.tabs(["🔴 Feed", "🛠️ Toolbox", "🧠 Strategic"])

# --- FEED ---
with tab1:
    col1, col2 = st.columns([4,1])
    if col2.button("🔄 Scan Now"):
        with st.spinner("Scanning..."):
            col = CTICollector()
            raw = col.fetch_all()
            proc = AIProcessor()
            an = proc.analyze_batch(raw)
            cnt = save_reports(raw, an)
            st.success(f"Saved {cnt} reports")
            time.sleep(1)
            st.rerun()

    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql("SELECT * FROM intel_reports ORDER BY id DESC", conn)
    conn.close()

    if not df.empty:
        for _, row in df.iterrows():
            sev_class = "critical" if "Critical" in row['severity'] else "high" if "High" in row['severity'] else ""
            st.markdown(f"""
            <div class="card">
                <span class="tag {sev_class}">{row['severity']}</span>
                <span class="tag">{row['category']}</span>
                <span style="color:#aaa; font-size:0.8em">{row['source']} | {row['published_at'][:16]}</span>
                <h4>{row['title']}</h4>
                <p>{row['summary']}</p>
                <a href="{row['url']}" target="_blank" style="color:#4da6ff">Read More</a>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No reports. Click Scan Now.")

# --- TOOLBOX ---
with tab2:
    ioc = st.text_input("Enter IOC (IP/Domain)")
    if st.button("Investigate"):
        tl = ThreatLookup(VT_KEY, US_KEY, AB_KEY)
        
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("VirusTotal")
            vt = tl.check_vt(ioc)
            if vt['status'] == 'found': st.write(vt['data'])
            else: st.write(vt['status'])
            
        with c2:
            st.subheader("URLScan")
            us = tl.check_urlscan(ioc)
            if us['status'] == 'found':
                st.image(us['data']['screenshot'])
                st.write(f"Verdict: {us['data'].get('verdict', 'Unknown')}")
            else: st.write(us['status'])
            
        st.divider()
        st.subheader("🤖 AI Analysis")
        proc = AIProcessor()
        with st.spinner("Analyzing..."):
            st.markdown(proc.analyze_ioc(ioc, {"vt": vt, "us": us}))

# --- STRATEGIC ---
with tab3:
    st.subheader("Active APT Groups")
    actors = APTCollector().get_actors()
    
    cols = st.columns(3)
    for i, actor in enumerate(actors):
        with cols[i%3]:
            with st.container(border=True):
                st.markdown(f"### {actor['name']}")
                st.markdown(f"**Origin:** {actor['origin']}")
                st.markdown(f"**Tools:** {actor['tools']}")
                if st.button(f"Hunt {actor['name']}", key=f"h_{i}"):
                    proc = AIProcessor()
                    with st.spinner("Generating Rules..."):
                        st.markdown(proc.generate_hunting(actor))
