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

# --- CUSTOM CSS (HIGH CONTRAST LIGHT CARDS) ---
st.markdown("""
<style>
    /* Global Text */
    html, body, [class*="css"] {
        font-family: 'Segoe UI', sans-serif;
    }
    
    /* Report Cards - High Contrast (White BG, Black Text) */
    .report-card {
        background-color: #ffffff;
        padding: 20px;
        border-radius: 10px;
        border-left: 6px solid #444; /* Default border */
        margin-bottom: 15px;
        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        color: #2c3e50; /* Dark text */
    }
    
    /* Border Colors based on severity (applied via inline style in python) */
    
    /* Tags Styling */
    .tag {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 4px;
        font-weight: 700;
        font-size: 0.8rem !important;
        margin-right: 8px;
        text-transform: uppercase;
    }
    
    .tag-time { background-color: #e0e0e0; color: #333; }
    
    .tag-critical { background-color: #ffcccc; color: #990000; border: 1px solid #cc0000; }
    .tag-high { background-color: #fff3cd; color: #856404; border: 1px solid #ffeeba; }
    .tag-medium { background-color: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
    .tag-low { background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
    
    .tag-israel { background-color: #cce5ff; color: #004085; border: 1px solid #b8daff; }
    
    /* Typography inside cards */
    .card-title {
        font-size: 1.3rem;
        font-weight: 700;
        margin: 10px 0;
        color: #000;
    }
    .card-summary {
        font-size: 1rem;
        color: #444;
        line-height: 1.5;
        margin-bottom: 15px;
    }
    .card-meta {
        font-size: 0.85rem;
        color: #666;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .read-more {
        color: #007bff;
        font-weight: bold;
        text-decoration: none;
    }
    .read-more:hover { text-decoration: underline; }
    
    /* Status Header */
    .status-header {
        background-color: #1e1e1e;
        color: #fff;
        padding: 10px 20px;
        border-radius: 8px;
        margin-bottom: 20px;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
</style>
""", unsafe_allow_html=True)

# --- AUTO REFRESH (15 Minutes) ---
REFRESH_MINUTES = 15
st_autorefresh(interval=REFRESH_MINUTES * 60 * 1000, key="auto_refresh")

init_db()

# --- INIT STATE ---
if 'ioc_data' not in st.session_state: st.session_state.ioc_data = None
if 'current_ioc' not in st.session_state: st.session_state.current_ioc = ""

# --- LOAD SECRETS ---
try: 
    GEMINI_KEY = st.secrets["gemini_key"]
    ABUSE_KEY = st.secrets.get("abuseipdb_key", "")
    VT_KEY = st.secrets.get("vt_key", "")
except FileNotFoundError:
    st.error("❌ Critical: secrets.toml not found. Please verify Streamlit Cloud settings.")
    st.stop()
except KeyError:
    st.error("❌ Critical: 'gemini_key' missing in secrets.")
    st.stop()

# --- TIME HELPERS ---
IL_TZ = pytz.timezone('Asia/Jerusalem')
def get_time_str(): return datetime.datetime.now(IL_TZ).strftime("%H:%M")
def get_next_update_str(): return (datetime.datetime.now(IL_TZ) + datetime.timedelta(minutes=REFRESH_MINUTES)).strftime("%H:%M")

st.title("🛡️ SOC War Room")

# --- AUTO-UPDATE HEADER ---
st.markdown(f"""
<div class="status-header">
    <span>📡 <b>System Status:</b> Operational (Auto-Mode)</span>
    <span>🕒 <b>Last Update:</b> {get_time_str()} | <b>Next Update:</b> {get_next_update_str()}</span>
</div>
""", unsafe_allow_html=True)

# --- SIDEBAR ---
with st.sidebar:
    st.header("⚙️ Controls")
    
    # 1. API Status (Secret Check Only)
    with st.expander("API Status", expanded=True):
        ok, msg = ConnectionManager.check_gemini(GEMINI_KEY)
        st.markdown(f"{'✅' if ok else '❌'} **AI Brain:** {msg}")
        
        if VT_KEY: st.markdown("✅ **VirusTotal:** Active")
        else: st.markdown("⚠️ **VirusTotal:** Missing Key")
    
    st.divider()
    
    # 2. Manual Scan Force
    if st.button("🚀 Force Update Now", type="primary"):
        with st.spinner("Fetching latest intelligence (Israel Time)..."):
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
tab_feed, tab_tools = st.tabs(["🔴 Live Feed", "🛠️ SOC Toolbox"])

with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    # Get all Data sorted by DATE (Newest first)
    df = pd.read_sql_query("SELECT * FROM intel_reports ORDER BY published_at DESC", conn)
    conn.close()

    # --- FILTERS ---
    col_f1, col_f2 = st.columns(2)
    
    # Get unique values for filters
    all_cats = df['category'].unique().tolist() if not df.empty else []
    all_sevs = df['severity'].unique().tolist() if not df.empty else []
    
    selected_cats = col_f1.multiselect("Filter by Category", options=all_cats, default=[])
    selected_sevs = col_f2.multiselect("Filter by Severity", options=all_sevs, default=[])

    # Apply Filters
    view_df = df
    if selected_cats:
        view_df = view_df[view_df['category'].isin(selected_cats)]
    if selected_sevs:
        view_df = view_df[view_df['severity'].isin(selected_sevs)]

    # --- DISPLAY FEED ---
    if view_df.empty:
        st.info("No reports match your filters. Try clearing them or running a scan.")
    else:
        for _, row in view_df.iterrows():
            # Date Formatting (Israel Time)
            try:
                dt_obj = parser.parse(row['published_at'])
                # Convert to Israel time for display if it's UTC
                if dt_obj.tzinfo is None: dt_obj = pytz.utc.localize(dt_obj)
                dt_il = dt_obj.astimezone(IL_TZ)
                display_date = dt_il.strftime("%d/%m %H:%M")
            except:
                display_date = row['published_at'][:16]

            # Dynamic Classes
            sev_low = row['severity'].lower()
            if "critical" in sev_low: sev_class = "tag-critical"
            elif "high" in sev_low: sev_class = "tag-high"
            elif "medium" in sev_low: sev_class = "tag-medium"
            else: sev_class = "tag-low"
            
            cat_class = "tag-israel" if "Israel" in row['category'] else "tag-medium"
            border_color = "#cc0000" if "Critical" in row['severity'] else "#444"

            st.markdown(f"""
            <div class="report-card" style="border-left: 6px solid {border_color};">
                <div style="margin-bottom:10px;">
                    <span class="tag tag-time">📅 {display_date} (IL)</span>
                    <span class="tag {sev_class}">{row['severity']}</span>
                    <span class="tag {cat_class}">{row['category']}</span>
                </div>
                <div class="card-title">{row['title']}</div>
                <div class="card-summary">{row['summary']}</div>
                <div class="card-meta">
                    <span><b>Source:</b> {row['source']} | <b>Impact:</b> {row['impact']}</span>
                    <a href="{row['url']}" target="_blank" class="read-more">Read Full Article ↗</a>
                </div>
            </div>""", unsafe_allow_html=True)

with tab_tools:
    st.markdown("<div class='tool-box'><h3>🛠️ Analyst Investigation Suite</h3><p>Enter an IOC to scan across all connected engines.</p></div>", unsafe_allow_html=True)
    
    ioc_col, btn_col = st.columns([4,1])
    ioc_input = ioc_col.text_input("Enter Indicator (IP / Domain / Hash)", placeholder="e.g. 1.1.1.1")
    
    # 1. SCAN ACTION
    if btn_col.button("🔍 Scan IOC", use_container_width=True):
        if not ioc_input:
            st.warning("Please enter an indicator.")
        else:
            st.session_state.current_ioc = ioc_input
            st.session_state.ioc_data = {} 
            
            with st.status("Running Investigation Tools...", expanded=True) as status:
                tl = ThreatLookup(vt_key=VT_KEY, abuse_ch_key="")
                
                st.write("Checking VirusTotal...")
                vt_res = tl.query_virustotal(ioc_input)
                
                st.write("Checking AbuseIPDB...")
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc_input):
                    ab_res = tl.query_abuseipdb(ioc_input, ABUSE_KEY)
                else:
                    ab_res = {"status": "skipped", "msg": "Not an IP"}
                
                st.write("Checking ThreatFox & URLhaus...")
                tf_res = tl.query_threatfox(ioc_input)
                uh_res = tl.query_urlhaus(ioc_input)
                
                st.session_state.ioc_data = {
                    "virustotal": vt_res,
                    "abuseipdb": ab_res,
                    "threatfox": tf_res,
                    "urlhaus": uh_res
                }
                status.update(label="Scan Complete!", state="complete", expanded=False)

    # 2. DISPLAY RAW RESULTS
    if st.session_state.ioc_data:
        st.divider()
        st.subheader(f"📊 Results for: {st.session_state.current_ioc}")
        
        t1, t2, t3, t4 = st.tabs(["VirusTotal", "AbuseIPDB", "ThreatFox", "URLhaus"])
        
        with t1:
            vt = st.session_state.ioc_data.get('virustotal', {})
            if vt.get('status') == 'found':
                stats = vt.get('stats', {})
                col1, col2 = st.columns(2)
                col1.metric("Malicious", stats.get('malicious', 0), delta_color="inverse")
                col1.metric("Suspicious", stats.get('suspicious', 0), delta_color="inverse")
                col2.json(stats)
            else:
                st.info(f"VirusTotal Status: {vt.get('status', 'Unknown')}")

        with t2:
            ab = st.session_state.ioc_data.get('abuseipdb', {})
            if ab.get('success'):
                d = ab['data']
                st.metric("Abuse Score", f"{d.get('abuseConfidenceScore')}%")
                st.write(f"**ISP:** {d.get('isp')} ({d.get('countryCode')})")
            else:
                st.info(ab.get('error', 'Not Applicable'))

        with t3:
            st.json(st.session_state.ioc_data.get('threatfox', {}))
        with t4:
            st.json(st.session_state.ioc_data.get('urlhaus', {}))

        # 3. AI SUMMARY ACTION
        st.divider()
        if st.button("✨ Analyze Findings with AI Analyst", type="primary"):
            with st.spinner("AI Analyst is reading the reports..."):
                proc = AIBatchProcessor(GEMINI_KEY)
                context = {
                    "ioc": st.session_state.current_ioc,
                    "raw_data": st.session_state.ioc_data
                }
                report = asyncio.run(proc.analyze_single_ioc(st.session_state.current_ioc, context))
                
                st.markdown("---")
                st.markdown("### 🤖 Incident Report")
                st.markdown(report)
