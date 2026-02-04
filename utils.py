import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import datetime
import pytz
import streamlit.components.v1 as components
from streamlit_autorefresh import st_autorefresh
from utils import *
from dateutil import parser

st.set_page_config(page_title="CTI War Room", layout="wide", page_icon="🛡️")

# CSS for Dark Text & Visibility
st.markdown("""
<style>
    .report-card { background-color: #fff; padding: 15px; border-radius: 8px; border-left: 5px solid #333; margin-bottom: 10px; color: #111 !important; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .card-title { font-weight: bold; font-size: 1.1rem; color: #000; }
    .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-right: 5px; }
    .tag-critical { background: #ffcccc; color: #990000; }
    .tag-israel { background: #cce5ff; color: #004085; }
</style>
""", unsafe_allow_html=True)

REFRESH_MINUTES = 15
st_autorefresh(interval=REFRESH_MINUTES * 60 * 1000, key="auto_refresh")
init_db()

GROQ_KEY = st.secrets.get("groq_key", "")
VT_KEY = st.secrets.get("vt_key", "")
URLSCAN_KEY = st.secrets.get("urlscan_key", "")
ABUSE_KEY = st.secrets.get("abuseipdb_key", "")

IL_TZ = pytz.timezone('Asia/Jerusalem')

with st.sidebar:
    st.header("⚙️ Settings")
    ok, msg = ConnectionManager.check_groq(GROQ_KEY)
    st.write(f"Groq AI: {'✅' if ok else '❌'} ({msg})")
    if st.button("🚀 Force Global Update", type="primary"):
        with st.status("Updating Feeds...", expanded=True):
            async def run_update():
                col, proc = CTICollector(), AIBatchProcessor(GROQ_KEY)
                raw = await col.get_all_data()
                if not raw: return 0
                analyzed = await proc.analyze_batch(raw)
                return save_reports(raw, analyzed)
            count = asyncio.run(run_update())
            st.success(f"Added {count} items.")
            st.rerun()

tab_feed, tab_tools, tab_strat, tab_map = st.tabs(["🔴 Live Feed", "🛠️ SOC Toolbox", "🧠 Strategic Intel", "🌍 Global Map"])

with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM intel_reports ORDER BY published_at DESC LIMIT 50", conn)
    conn.close()
    if df.empty: st.info("No data yet. Run update.")
    else:
        for _, row in df.iterrows():
            sev_class = "tag-critical" if "Critical" in row['severity'] else ""
            cat_class = "tag-israel" if "Israel" in row['category'] else ""
            st.markdown(f"""
            <div class="report-card">
                <span class="tag {sev_class}">{row['severity']}</span>
                <span class="tag {cat_class}">{row['category']}</span>
                <div class="card-title">{row['title']}</div>
                <div style="margin: 5px 0;">{row['summary']}</div>
                <div style="font-size: 0.8rem; color: #666;">Source: {row['source']} | <a href="{row['url']}">Link</a></div>
            </div>
            """, unsafe_allow_html=True)

with tab_tools:
    st.subheader("🛠️ SOC Toolbox - IOC Investigation")
    ioc = st.text_input("Enter IP, Domain or Hash")
    if st.button("Investigate"):
        tl = ThreatLookup(VT_KEY, URLSCAN_KEY, ABUSE_KEY)
        results = {}
        
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown("### VirusTotal")
            vt = tl.query_virustotal(ioc)
            if vt:
                results['virustotal'] = vt
                st.json(vt.get('last_analysis_stats', {}))
            else: st.warning("No data found.")
            
        with c2:
            st.markdown("### URLScan.io")
            us = tl.query_urlscan(ioc)
            if us:
                results['urlscan'] = us
                st.write(f"Verdict: {us.get('verdict', {}).get('overall')}")
                if us.get('screenshot'): st.image(us['screenshot'])
            else: st.warning("No data found.")
            
        with c3:
            st.markdown("### AbuseIPDB")
            ab = tl.query_abuseipdb(ioc)
            if ab:
                results['abuseipdb'] = ab
                st.metric("Abuse Confidence", f"{ab.get('abuseConfidenceScore')}%")
                st.write(f"ISP: {ab.get('isp')}")
            else: st.warning("No data found.")
            
        st.divider()
        if st.button("🤖 Generate Professional AI Report"):
            with st.spinner("AI analyzing all results..."):
                proc = AIBatchProcessor(GROQ_KEY)
                report = asyncio.run(proc.analyze_single_ioc(ioc, results))
                st.markdown(report)

with tab_strat:
    st.subheader("🧠 Strategic Intel")
    threats = APTSheetCollector().fetch_threats()
    for actor in threats:
        with st.expander(f"Actor: {actor['name']} ({actor['origin']})"):
            st.write(actor['desc'])
            if st.button(f"Generate Hunt for {actor['name']}"):
                proc = AIBatchProcessor(GROQ_KEY)
                res = asyncio.run(proc.generate_hunting_queries(actor))
                st.markdown(res)

with tab_map:
    components.iframe("https://threatmap.checkpoint.com/", height=600)
