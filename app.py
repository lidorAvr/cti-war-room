import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import datetime
import pytz
import streamlit.components.v1 as components
from streamlit_autorefresh import st_autorefresh
from utils import *
from dateutil import parser as date_parser

# --- CONFIGURATION ---
st.set_page_config(page_title="CTI War Room", layout="wide", page_icon="🛡️")

# --- UI STYLING ---
st.markdown("""
<style>
    .report-card { background-color: #fff; padding: 15px; border-radius: 8px; border-left: 5px solid #333; margin-bottom: 10px; color: #111 !important; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .card-title { font-weight: bold; font-size: 1.1rem; color: #000 !important; margin: 5px 0; }
    .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-right: 5px; }
    .tag-critical { background: #ffcccc; color: #990000; }
    .tag-israel { background: #cce5ff; color: #004085; }
    .tag-time { background: #f0f0f0; color: #666; }
    a { text-decoration: none; color: #0066cc !important; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

# --- INITIALIZATION ---
init_db() 

REFRESH_MINUTES = 15
st_autorefresh(interval=REFRESH_MINUTES * 60 * 1000, key="auto_refresh")

GROQ_KEY = st.secrets.get("groq_key", "")
VT_KEY = st.secrets.get("vt_key", "")
URLSCAN_KEY = st.secrets.get("urlscan_key", "")
ABUSE_KEY = st.secrets.get("abuseipdb_key", "")

IL_TZ = pytz.timezone('Asia/Jerusalem')

# --- SIDEBAR ---
with st.sidebar:
    st.header("⚙️ Status")
    ok, msg = ConnectionManager.check_groq(GROQ_KEY)
    st.write(f"Groq AI: {'✅' if ok else '❌'} ({msg})")
    
    if st.button("🚀 Force Global Update", type="primary"):
        with st.status("Fetching New Intelligence...", expanded=True):
            async def run_update():
                col, proc = CTICollector(), AIBatchProcessor(GROQ_KEY)
                raw = await col.get_all_data()
                if not raw: return 0
                analyzed = await proc.analyze_batch(raw)
                return save_reports(raw, analyzed)
            count = asyncio.run(run_update())
            st.success(f"Discovered {count} new items.")
            st.rerun()

# --- MAIN TABS ---
tab_feed, tab_tools, tab_strat, tab_map = st.tabs(["🔴 Live Feed", "🛠️ SOC Toolbox", "🧠 Strategic Intel", "🌍 Global Map"])

with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM intel_reports ORDER BY published_at DESC", conn)
    conn.close()
    
    if df.empty:
        st.info("No active threats in the last 48 hours. Use Force Update.")
    else:
        now = datetime.datetime.now(IL_TZ)
        for _, row in df.iterrows():
            pub_date = date_parser.parse(row['published_at'])
            if pub_date.tzinfo is None: pub_date = pytz.utc.localize(pub_date).astimezone(IL_TZ)
            
            # Skip if older than 48h (Final UI Filter)
            if (now - pub_date).total_seconds() > 172800: continue

            sev_class = "tag-critical" if "Critical" in row['severity'] else ""
            cat_class = "tag-israel" if "Israel" in row['category'] else ""
            
            st.markdown(f"""
            <div class="report-card">
                <span class="tag tag-time">{pub_date.strftime('%d/%m %H:%M')}</span>
                <span class="tag {sev_class}">{row['severity']}</span>
                <span class="tag {cat_class}">{row['category']}</span>
                <div class="card-title">{row['title']}</div>
                <div style="margin: 5px 0; color: #333;">{row['summary']}</div>
                <div style="font-size: 0.8rem; color: #666;">Source: {row['source']} | <a href="{row['url']}" target="_blank">Full Report ↗</a></div>
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
    st.subheader("🧠 Strategic Threat Intel")
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
