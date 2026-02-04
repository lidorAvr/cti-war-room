import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import re
import datetime
import pytz
import streamlit.components.v1 as components
from streamlit_autorefresh import st_autorefresh
from utils import * from dateutil import parser

# --- CONFIGURATION ---
st.set_page_config(
    page_title="SOC War Room | Israel Focus", 
    layout="wide", 
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# --- CUSTOM CSS ---
st.markdown("""
<style>
    html, body, [class*="css"] { font-family: 'Segoe UI', sans-serif; }
    .report-card {
        background-color: #ffffff; padding: 20px; border-radius: 12px;
        border-left: 6px solid #444; margin-bottom: 15px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1); color: #1a1a1a !important;
        transition: transform 0.2s;
    }
    .report-card:hover { transform: translateY(-2px); }
    .card-title { font-size: 1.2rem; font-weight: 800; margin-bottom: 8px; color: #000; }
    .card-summary { font-size: 1rem; color: #333; line-height: 1.5; margin-bottom: 12px; }
    .card-meta { font-size: 0.85rem; color: #666; display: flex; justify-content: space-between; border-top: 1px solid #eee; padding-top: 8px;}
    .tag { display: inline-block; padding: 3px 10px; border-radius: 12px; font-weight: 700; font-size: 0.75rem; margin-right: 6px; }
    .tag-critical { background-color: #ffe6e6; color: #b30000; border: 1px solid #ffcccc; }
    .tag-high { background-color: #fff8e1; color: #b38f00; border: 1px solid #ffeeba; }
    .tag-medium { background-color: #e6f7ff; color: #006699; border: 1px solid #b8daff; }
    .tag-israel { background-color: #e8f4fd; color: #0056b3; border: 1px solid #badce3; }
    a { text-decoration: none; color: #0066cc !important; font-weight: bold; }
    .status-header {
        background-color: #f8f9fa; color: #333; padding: 10px 15px;
        border-radius: 8px; border: 1px solid #e9ecef; margin-bottom: 20px;
        display: flex; justify-content: space-between; align-items: center;
    }
</style>
""", unsafe_allow_html=True)

# --- AUTO REFRESH ---
REFRESH_MINUTES = 15
st_autorefresh(interval=REFRESH_MINUTES * 60 * 1000, key="auto_refresh")

init_db()

# --- STATE ---
if 'filter_type' not in st.session_state: st.session_state.filter_type = 'All'
if 'ioc_data' not in st.session_state: st.session_state.ioc_data = {}
if 'current_ioc' not in st.session_state: st.session_state.current_ioc = ""

# --- SAFE SECRETS LOADING ---
GROQ_KEY = st.secrets.get("groq_key", "")
ABUSE_KEY = st.secrets.get("abuseipdb_key", "")
VT_KEY = st.secrets.get("vt_key", "")
URLSCAN_KEY = st.secrets.get("urlscan_key", "")

# --- HELPERS ---
IL_TZ = pytz.timezone('Asia/Jerusalem')
def get_time_str(): return datetime.datetime.now(IL_TZ).strftime("%H:%M")
def get_next_update_str(): return (datetime.datetime.now(IL_TZ) + datetime.timedelta(minutes=REFRESH_MINUTES)).strftime("%H:%M")

# --- HEADER ---
st.title("🛡️ SOC War Room")
st.caption("Powered by Groq AI (Llama 3) | Real-time Israel Threat Intel")

st.markdown(f"""
<div class="status-header">
    <span>🚀 <b>AI Engine:</b> Groq (Llama-3.1-8b) | <b>Status:</b> {'Online ✅' if GROQ_KEY else 'Offline ❌'}</span>
    <span>🕒 <b>Last:</b> {get_time_str()} | <b>Next:</b> {get_next_update_str()}</span>
</div>
""", unsafe_allow_html=True)

# --- SIDEBAR ---
with st.sidebar:
    st.header("⚙️ Controls")
    
    with st.expander("API Status", expanded=True):
        ok, msg = ConnectionManager.check_groq(GROQ_KEY)
        st.write(f"{'✅' if ok else '❌'} **Groq AI:** {msg}")
        st.write(f"{'✅' if VT_KEY else '⚠️'} **VirusTotal**")
        st.write(f"{'✅' if URLSCAN_KEY else '⚠️'} **URLScan**")
    
    st.divider()
    
    # UPDATE BUTTON
    if st.button("🚀 Force Global Update", type="primary"):
        with st.status("🔄 Scanning & Analyzing (Groq Fast Mode)...", expanded=True) as status:
            async def run_update():
                col = CTICollector()
                proc = AIBatchProcessor(GROQ_KEY)
                
                # 1. Fetch
                st.write("Fetching feeds...")
                raw_items = await col.get_all_data()
                if not raw_items: return 0
                
                # 2. Analyze
                st.write(f"Analyzing {len(raw_items)} items with AI...")
                analyzed_items = await proc.analyze_batch(raw_items)
                
                # 3. Save
                st.write("Saving to DB...")
                count = save_reports(raw_items, analyzed_items)
                return count

            try:
                new_count = asyncio.run(run_update())
                status.update(label=f"Done! +{new_count} Reports.", state="complete", expanded=False)
                if new_count > 0: st.rerun()
                else: st.toast("No new reports found.")
            except Exception as e:
                st.error(f"Update Error: {e}")

# --- TABS ---
tab_feed, tab_tools, tab_strat, tab_map = st.tabs(["🔴 Live Feed", "🛠️ SOC Toolbox", "🧠 Strategic Intel", "🌍 Global Map"])

# ---------------- TAB 1: LIVE FEED ----------------
with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM intel_reports ORDER BY published_at DESC LIMIT 100", conn)
    conn.close()

    c1, c2, c3, c4 = st.columns(4)
    # Safe filtering with fallback
    count_crit = len(df[df['severity'].str.contains('Critical', case=False, na=False)]) if not df.empty else 0
    count_il = len(df[df['category'].str.contains('Israel', case=False, na=False)]) if not df.empty else 0
    
    if c1.button(f"🚨 Critical ({count_crit})", use_container_width=True): st.session_state.filter_type = 'Critical'
    if c2.button(f"🇮🇱 Israel ({count_il})", use_container_width=True): st.session_state.filter_type = 'Israel'
    if c3.button(f"🦠 Malware", use_container_width=True): st.session_state.filter_type = 'Malware'
    if c4.button(f"Show All ({len(df)})", use_container_width=True): st.session_state.filter_type = 'All'

    view_df = df
    if st.session_state.filter_type == 'Critical': view_df = df[df['severity'].str.contains('Critical', case=False, na=False)]
    elif st.session_state.filter_type == 'Israel': view_df = df[df['category'].str.contains('Israel', case=False, na=False)]
    elif st.session_state.filter_type == 'Malware': view_df = df[df['category'].str.contains('Malware', case=False, na=False)]

    if view_df.empty:
        st.info("No reports found.")
    else:
        for index, row in view_df.iterrows():
            try:
                dt_obj = parser.parse(row['published_at'])
                if dt_obj.tzinfo is None: dt_obj = pytz.utc.localize(dt_obj)
                display_date = dt_obj.astimezone(IL_TZ).strftime("%d/%m %H:%M")
            except: display_date = str(row['published_at'])[:16]

            sev = row['severity'] or "Medium"
            cat = row['category'] or "General"
            
            bord_col = "#cc0000" if "Critical" in sev else ("#ff8800" if "High" in sev else "#444")
            sev_cls = "tag-critical" if "Critical" in sev else ("tag-high" if "High" in sev else "tag-medium")
            cat_cls = "tag-israel" if "Israel" in cat else "tag-medium"

            st.markdown(f"""
            <div class="report-card" style="border-left: 6px solid {bord_col};">
                <div style="margin-bottom:10px;">
                    <span class="tag" style="background:#eee;">{display_date}</span>
                    <span class="tag {sev_cls}">{sev}</span>
                    <span class="tag {cat_cls}">{cat}</span>
                </div>
                <div class="card-title">{row['title']}</div>
                <div class="card-summary">{row['summary']}</div>
                <div class="card-meta">
                    <span><b>Src:</b> {row['source']}</span>
                    <a href="{row['url']}" target="_blank">Open Link ↗</a>
                </div>
            </div>""", unsafe_allow_html=True)

# ---------------- TAB 2: TOOLBOX ----------------
with tab_tools:
    st.subheader("🛠️ IOC Enrichment")
    c1, c2 = st.columns([4,1])
    ioc = c1.text_input("Indicator (IP/Domain/Hash)", key="ioc_in")
    
    if c2.button("Scan", use_container_width=True) and ioc:
        st.session_state.current_ioc = ioc
        st.session_state.ioc_data = {}
        with st.status("Querying Engines...", expanded=True) as status:
            tl = ThreatLookup(vt_key=VT_KEY, urlscan_key=URLSCAN_KEY, abuse_ch_key=ABUSE_KEY)
            
            st.session_state.ioc_data['virustotal'] = tl.query_virustotal(ioc)
            st.session_state.ioc_data['urlscan'] = tl.query_urlscan(ioc)
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', ioc):
                st.session_state.ioc_data['abuseipdb'] = tl.query_abuseipdb(ioc, ABUSE_KEY)
            st.session_state.ioc_data['threatfox'] = tl.query_threatfox(ioc)
            status.update(label="Complete", state="complete", expanded=False)

    if st.session_state.ioc_data:
        st.divider()
        st.subheader(f"Results: {st.session_state.current_ioc}")
        t1, t2, t3, t4 = st.tabs(["VirusTotal", "URLScan", "Raw Data", "AI Analysis"])
        
        with t1:
            d = st.session_state.ioc_data.get('virustotal', {})
            if d.get('status') == 'found':
                st.metric("Malicious", d.get('stats', {}).get('malicious', 0))
                st.json(d.get('stats'))
            else: st.write("Not Found")
            
        with t2:
            d = st.session_state.ioc_data.get('urlscan', {})
            if d.get('status') == 'found':
                st.write(f"Verdict: {d.get('verdict', {}).get('overall')}")
                if d.get('screenshot'): st.image(d['screenshot'])
            else: st.write("Not Found")

        with t3: st.json(st.session_state.ioc_data)

        with t4:
            if st.button("🤖 Ask Groq AI"):
                with st.spinner("Analyzing..."):
                    proc = AIBatchProcessor(GROQ_KEY)
                    res = asyncio.run(proc.analyze_single_ioc(st.session_state.current_ioc, st.session_state.ioc_data))
                    st.markdown(res)

# ---------------- TAB 3: STRATEGIC ----------------
with tab_strat:
    st.subheader("🧠 APT Tracker")
    col = APTSheetCollector()
    threats = col.fetch_threats()
    
    cols = st.columns(3)
    for i, actor in enumerate(threats):
        with cols[i % 3]:
            with st.container(border=True):
                st.markdown(f"#### {actor['origin']} {actor['name']}")
                st.caption(actor['type'])
                st.write(actor['desc'])
                st.markdown(f"**Target:** {actor['target']}")
                
                if st.button(f"🏹 Hunt {actor['name']}", key=f"h_{i}"):
                    with st.spinner("Generating Queries..."):
                        proc = AIBatchProcessor(GROQ_KEY)
                        q = asyncio.run(proc.generate_hunting_queries(actor))
                        st.markdown(q)

# ---------------- TAB 4: MAP ----------------
with tab_map:
    st.subheader("🌍 Global Threat Map")
    components.iframe("https://threatmap.checkpoint.com/", height=600, scrolling=False)
    
    if st.button("🤖 Analyze Global Trends"):
        with st.spinner("AI Thinking..."):
            conn = sqlite3.connect(DB_NAME)
            df_map = pd.read_sql_query("SELECT title FROM intel_reports LIMIT 30", conn)
            conn.close()
            
            proc = AIBatchProcessor(GROQ_KEY)
            prompt = f"Summarize top 3 global cyber trends based on: {df_map.to_string()}"
            res = asyncio.run(query_groq_api(GROQ_KEY, prompt))
            st.markdown(res)
