import streamlit as st
import pandas as pd
import sqlite3
import time
import streamlit.components.v1 as components
from streamlit_autorefresh import st_autorefresh
from utils import *

st.set_page_config(page_title="SOC War Room", layout="wide", page_icon="🛡️")

st.markdown("""<style>
.card { background-color: #ffffff; padding: 15px; border-radius: 8px; margin-bottom: 10px; border-left: 5px solid #444; box-shadow: 0 2px 5px rgba(0,0,0,0.1); color: #333; }
.card h4 { margin: 0; color: #000; font-size: 1.1em; }
.card p { color: #555; font-size: 0.9em; margin: 5px 0; }
.meta { font-size: 0.8em; color: #777; display: flex; justify-content: space-between; }
.tag { padding: 2px 6px; border-radius: 4px; font-weight: bold; font-size: 0.75em; margin-right: 5px; }
.critical { background: #ffe6e6; color: #cc0000; border: 1px solid #cc0000; }
.high { background: #fff8e1; color: #f57f17; border: 1px solid #f57f17; }
</style>""", unsafe_allow_html=True)

st_autorefresh(interval=15 * 60 * 1000, key="auto_refresh")
init_db()

try:
    GENAI_KEY = st.secrets["gemini_key"]
    VT_KEY = st.secrets.get("vt_key", "")
    US_KEY = st.secrets.get("urlscan_key", "")
    AB_KEY = st.secrets.get("abuseipdb_key", "")
except:
    st.error("Secrets Error. Check .streamlit/secrets.toml")
    st.stop()

st.title("🛡️ SOC War Room")

# Sidebar
with st.sidebar:
    st.header("⚙️ Controls")
    if st.button("🚀 Global Update", type="primary"):
        with st.spinner("Fetching Data..."):
            col = CTICollector()
            ai = AIHandler(GENAI_KEY)
            raw = col.fetch_all()
            analyzed = ai.analyze_batch(raw)
            cnt = save_reports(raw, analyzed)
            st.success(f"Added {cnt} reports")
            time.sleep(1)
            st.rerun()
    
    st.info(f"AI Status: {'✅' if GENAI_KEY else '❌'}")

# Tabs
tab1, tab2, tab3, tab4 = st.tabs(["Feed", "Toolbox", "Strategic", "Map"])

with tab1:
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql("SELECT * FROM intel_reports ORDER BY id DESC LIMIT 50", conn)
    conn.close()
    
    if not df.empty:
        c1, c2, c3, c4 = st.columns(4)
        c4.metric("Total Reports", len(df))
        
        for _, row in df.iterrows():
            sev = row['severity']
            cls = "critical" if "Critical" in sev else "high" if "High" in sev else ""
            st.markdown(f"""
            <div class="card">
                <div><span class="tag {cls}">{sev}</span> <span class="tag">{row['category']}</span></div>
                <h4>{row['title']}</h4>
                <p>{row['summary']}</p>
                <div class="meta">
                    <span>{row['source']} | {row['published_at'][:16]}</span>
                    <a href="{row['url']}" target="_blank">Read More</a>
                </div>
            </div>""", unsafe_allow_html=True)
    else:
        st.info("No reports. Click 'Global Update'.")

with tab2:
    ioc = st.text_input("IOC Investigation")
    if st.button("Check"):
        tl = ThreatLookup(VT_KEY, US_KEY, AB_KEY)
        c1, c2 = st.columns(2)
        with c1:
            st.caption("VirusTotal")
            st.write(tl.check_vt(ioc))
        with c2:
            st.caption("URLScan")
            res = tl.check_urlscan(ioc)
            if res['status'] == 'found':
                st.image(res['data']['screenshot'])
                st.write(f"Verdict: {res['data'].get('verdict', {}).get('overall', 'N/A')}")
            else: st.write(res)

with tab3:
    st.subheader("APT Hunting")
    actors = APTData.get_actors()
    cols = st.columns(3)
    for i, a in enumerate(actors):
        with cols[i%3]:
            with st.container(border=True):
                st.markdown(f"**{a['name']}** ({a['origin']})")
                st.caption(f"Tools: {a['tools']}")
                if st.button("Hunt", key=f"h_{i}"):
                    ai = AIHandler(GENAI_KEY)
                    with st.spinner("Generating..."):
                        st.markdown(ai.generate_hunting(a))

with tab4:
    components.iframe("https://threatmap.checkpoint.com/", height=600)
