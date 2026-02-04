import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import base64
import json
import re
import datetime
import pytz
from streamlit_autorefresh import st_autorefresh
from utils import *
from dateutil import parser

# --- CONFIGURATION ---
st.set_page_config(page_title="SOC War Room", layout="wide", page_icon="🛡️")

# --- CUSTOM CSS ---
st.markdown("""
<style>
    /* Global Settings */
    html, body, [class*="css"] {
        font-family: 'Segoe UI', sans-serif;
    }
    
    /* Feed Cards - White BG, Dark Text */
    .report-card {
        background-color: #ffffff;
        padding: 20px;
        border-radius: 10px;
        border-left: 6px solid #444;
        margin-bottom: 15px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        color: #1a1a1a; /* Darker text */
    }
    
    /* Tags */
    .tag {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.8rem !important;
        margin-right: 8px;
        text-transform: uppercase;
    }
    .tag-time { background-color: #f0f0f0; color: #333; border: 1px solid #ddd; }
    
    .tag-critical { background-color: #ffcccc; color: #990000; border: 1px solid #cc0000; }
    .tag-high { background-color: #fff3cd; color: #856404; border: 1px solid #ffeeba; }
    .tag-israel { background-color: #d6eaff; color: #004085; border: 1px solid #b8daff; }
    .tag-medium { background-color: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
    
    /* Card Typography */
    .card-title { font-size: 1.25rem; font-weight: 700; margin: 8px 0; color: #000; }
    .card-summary { font-size: 1rem; color: #333; line-height: 1.5; margin-bottom: 12px; }
    .card-meta { font-size: 0.85rem; color: #555; display: flex; justify-content: space-between; }
    a { text-decoration: none; color: #0066cc; font-weight: bold; }
    
    /* Status Header */
    .status-header {
        background-color: #f8f9fa;
        color: #333;
        padding: 10px 15px;
        border-radius: 8px;
        border: 1px solid #ddd;
        margin-bottom: 20px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
</style>
""", unsafe_allow_html=True)

# --- AUTO REFRESH ---
REFRESH_MINUTES = 15
st_autorefresh(interval=REFRESH_MINUTES * 60 * 1000, key="auto_refresh")
init_db()

# --- INIT STATE ---
if 'filter_type' not in st.session_state: st.session_state.filter_type = 'All'
if 'ioc_data' not in st.session_state: st.session_state.ioc_data = None
if 'current_ioc' not in st.session_state: st.session_state.current_ioc = ""

# --- LOAD SECRETS ---
try: 
    GEMINI_KEY = st.secrets["gemini_key"]
    ABUSE_KEY = st.secrets.get("abuseipdb_key", "")
    VT_KEY = st.secrets.get("vt_key", "")
    URLSCAN_KEY = st.secrets.get("urlscan_key", "")
except:
    st.error("Secrets not loaded correctly.")
    st.stop()

# --- HELPERS ---
IL_TZ = pytz.timezone('Asia/Jerusalem')
def get_time_str(): return datetime.datetime.now(IL_TZ).strftime("%H:%M")
def get_next_update_str(): return (datetime.datetime.now(IL_TZ) + datetime.timedelta(minutes=REFRESH_MINUTES)).strftime("%H:%M")

st.title("🛡️ SOC War Room")

st.markdown(f"""
<div class="status-header">
    <span>📡 <b>System:</b> Online | <b>Refresh:</b> Every {REFRESH_MINUTES}m</span>
    <span>🕒 <b>Last:</b> {get_time_str()} | <b>Next:</b> {get_next_update_str()}</span>
</div>
""", unsafe_allow_html=True)

# --- SIDEBAR ---
with st.sidebar:
    st.header("⚙️ Controls")
    
    with st.expander("API Status", expanded=True):
        ok, msg = ConnectionManager.check_gemini(GEMINI_KEY)
        st.write(f"{'✅' if ok else '❌'} **AI Brain:** {msg}")
        st.write(f"{'✅' if VT_KEY else '⚠️'} **VirusTotal**")
        st.write(f"{'✅' if URLSCAN_KEY else '⚠️'} **URLScan**")
    
    st.divider()
    
    if st.button("🚀 Force Global Update", type="primary"):
        with st.spinner("Fetching Intelligence..."):
            async def scan():
                col = CTICollector()
                proc = AIBatchProcessor(GEMINI_KEY)
                raw = await col.get_all_data()
                analyzed = await proc.analyze_batch(raw)
                return save_reports(raw, analyzed)
            
            c = asyncio.run(scan())
            st.success(f"Updated! {c} new items.")
            st.rerun()

# --- TABS ---
tab_feed, tab_tools, tab_strat = st.tabs(["🔴 Live Feed", "🛠️ SOC Toolbox", "🧠 Strategic Intel"])

with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM intel_reports ORDER BY published_at DESC", conn)
    conn.close()

    # --- BUTTON FILTERS (RESTORED) ---
    c1, c2, c3, c4 = st.columns(4)
    
    # Counts
    count_crit = len(df[df['severity'].str.contains('Critical', case=False)])
    count_il = len(df[df['category'].str.contains('Israel', case=False)])
    count_mal = len(df[df['category'].str.contains('Malware', case=False)])
    
    if c1.button(f"🚨 Critical ({count_crit})", use_container_width=True): st.session_state.filter_type = 'Critical'
    if c2.button(f"🇮🇱 Israel ({count_il})", use_container_width=True): st.session_state.filter_type = 'Israel'
    if c3.button(f"🦠 Malware ({count_mal})", use_container_width=True): st.session_state.filter_type = 'Malware'
    if c4.button("🌐 Show All", use_container_width=True): st.session_state.filter_type = 'All'

    # Filter Logic
    view_df = df
    if st.session_state.filter_type == 'Critical': view_df = df[df['severity'].str.contains('Critical', case=False)]
    elif st.session_state.filter_type == 'Israel': view_df = df[df['category'].str.contains('Israel', case=False)]
    elif st.session_state.filter_type == 'Malware': view_df = df[df['category'].str.contains('Malware', case=False)]

    if view_df.empty:
        st.info(f"No reports found for filter: {st.session_state.filter_type}")
    else:
        for _, row in view_df.iterrows():
            # Date Formatting
            try:
                dt_obj = parser.parse(row['published_at'])
                if dt_obj.tzinfo is None: dt_obj = pytz.utc.localize(dt_obj)
                dt_il = dt_obj.astimezone(IL_TZ)
                display_date = dt_il.strftime("%d/%m %H:%M")
            except: display_date = row['published_at']

            # Styles
            sev = row['severity']
            bord = "#cc0000" if "Critical" in sev else ("#ff8800" if "High" in sev else "#444")
            sev_cls = "tag-critical" if "Critical" in sev else ("tag-high" if "High" in sev else "tag-medium")
            
            st.markdown(f"""
            <div class="report-card" style="border-left: 6px solid {bord};">
                <div style="margin-bottom:10px;">
                    <span class="tag tag-time">{display_date}</span>
                    <span class="tag {sev_cls}">{sev}</span>
                    <span class="tag tag-medium">{row['category']}</span>
                </div>
                <div class="card-title">{row['title']}</div>
                <div class="card-summary">{row['summary']}</div>
                <div class="card-meta">
                    <span><b>Src:</b> {row['source']}</span>
                    <a href="{row['url']}" target="_blank">Read More ↗</a>
                </div>
            </div>""", unsafe_allow_html=True)

with tab_tools:
    st.markdown("<div class='tool-box'><h3>🛠️ Analyst Investigation Suite</h3></div>", unsafe_allow_html=True)
    
    ioc_col, btn_col = st.columns([4,1])
    ioc_input = ioc_col.text_input("Enter Indicator", placeholder="e.g. 1.1.1.1")
    
    if btn_col.button("🔍 Scan IOC", use_container_width=True):
        if ioc_input:
            st.session_state.current_ioc = ioc_input
            st.session_state.ioc_data = {}
            
            with st.status("Scanning Engines...", expanded=True) as status:
                tl = ThreatLookup(vt_key=VT_KEY, urlscan_key=URLSCAN_KEY, abuse_ch_key="")
                
                vt_res = tl.query_virustotal(ioc_input)
                st.write(f"VirusTotal: {vt_res.get('status')}")
                
                us_res = tl.query_urlscan(ioc_input)
                st.write(f"URLScan: {us_res.get('status')}")

                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc_input):
                    ab_res = tl.query_abuseipdb(ioc_input, ABUSE_KEY)
                else: ab_res = {"status": "skipped"}
                
                tf_res = tl.query_threatfox(ioc_input)
                uh_res = tl.query_urlhaus(ioc_input)
                
                st.session_state.ioc_data = {"virustotal": vt_res, "urlscan": us_res, "abuseipdb": ab_res, "threatfox": tf_res, "urlhaus": uh_res}
                status.update(label="Done!", state="complete", expanded=False)

    if st.session_state.ioc_data:
        st.divider()
        st.subheader(f"📊 Results: {st.session_state.current_ioc}")
        
        t1, t2, t3, t4, t5 = st.tabs(["VirusTotal", "URLScan", "AbuseIPDB", "ThreatFox", "URLhaus"])
        
        with t1:
            d = st.session_state.ioc_data.get('virustotal', {})
            if d.get('status') == 'found':
                c1, c2 = st.columns(2)
                c1.metric("Malicious", d['stats']['malicious'])
                c2.metric("Reputation", d.get('reputation'))
                st.json(d['stats'])
            else: st.info(d.get('msg', 'Not Found'))

        with t2:
            d = st.session_state.ioc_data.get('urlscan', {})
            if d.get('status') == 'found':
                st.write(f"**Verdict:** {d.get('verdict', {}).get('overall')}")
                if d.get('screenshot'): st.image(d['screenshot'])
            else: st.info("Not Found / No Key")

        with t3:
            d = st.session_state.ioc_data.get('abuseipdb', {})
            if d.get('success'):
                st.metric("Abuse Score", d['data']['abuseConfidenceScore'])
                st.write(f"ISP: {d['data']['isp']}")
            else: st.info(d.get('error', 'N/A'))
            
        with t4: st.json(st.session_state.ioc_data.get('threatfox', {}))
        with t5: st.json(st.session_state.ioc_data.get('urlhaus', {}))

        st.divider()
        if st.button("✨ Analyze with AI", type="primary"):
             with st.spinner("AI Analyzing..."):
                 proc = AIBatchProcessor(GEMINI_KEY)
                 rep = asyncio.run(proc.analyze_single_ioc(st.session_state.current_ioc, st.session_state.ioc_data))
                 st.markdown(rep)

with tab_strat:
    st.subheader("🧠 Strategic Intelligence: Active APT Groups")
    st.caption("Monitoring key threat actors targeting Israel and the Middle East.")
    
    col = APTSheetCollector()
    df_apt = col.fetch_threats("Israel")
    
    if not df_apt.empty:
        st.dataframe(
            df_apt,
            column_config={
                "Group": st.column_config.TextColumn("Threat Actor", help="Name of the APT Group"),
                "Origin": st.column_config.TextColumn("Origin", help="Suspected attribution"),
                "Type": st.column_config.TextColumn("Motivation", help="Espionage, Sabotage, etc."),
            },
            use_container_width=True,
            hide_index=True
        )
    else:
        st.info("Strategic database connection currently unavailable.")
