import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import base64
import json
import re
import datetime
import pytz
import streamlit.components.v1 as components
from streamlit_autorefresh import st_autorefresh
from utils import * # Imports the updated logic from the new utils.py
from dateutil import parser

# --- CONFIGURATION ---
st.set_page_config(
    page_title="SOC War Room | Israel Focus", 
    layout="wide", 
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# --- CUSTOM CSS (Optimized for Readability) ---
st.markdown("""
<style>
    /* Global Fonts */
    html, body, [class*="css"] { font-family: 'Segoe UI', sans-serif; }
    
    /* REPORT CARD DESIGN */
    .report-card {
        background-color: #ffffff;
        padding: 20px;
        border-radius: 12px;
        border-left: 6px solid #444; /* Default border color */
        margin-bottom: 15px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        color: #1a1a1a !important; /* Force Dark Text for readability */
        transition: transform 0.2s;
    }
    
    .report-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 12px rgba(0,0,0,0.15);
    }
    
    /* TYPOGRAPHY INSIDE CARDS */
    .card-title { 
        font-size: 1.3rem; 
        font-weight: 800; 
        margin-bottom: 8px; 
        color: #000000 !important; 
    }
    
    .card-summary { 
        font-size: 1rem; 
        color: #2c3e50 !important; 
        line-height: 1.6; 
        margin-bottom: 15px; 
    }
    
    .card-meta { 
        font-size: 0.9rem; 
        color: #555555 !important; 
        display: flex; 
        justify-content: space-between; 
        align-items: center;
        border-top: 1px solid #eee;
        padding-top: 10px;
    }
    
    /* TAGS */
    .tag { 
        display: inline-block; 
        padding: 4px 12px; 
        border-radius: 15px; 
        font-weight: 700; 
        font-size: 0.8rem !important; 
        margin-right: 8px; 
        text-transform: uppercase; 
        letter-spacing: 0.5px;
    }
    
    .tag-time { background-color: #f0f2f6; color: #444; border: 1px solid #dbe4ee; }
    
    /* SEVERITY TAGS */
    .tag-critical { background-color: #ffe6e6; color: #b30000; border: 1px solid #ffcccc; }
    .tag-high { background-color: #fff8e1; color: #b38f00; border: 1px solid #ffeeba; }
    .tag-medium { background-color: #e6f7ff; color: #006699; border: 1px solid #b8daff; }
    .tag-low { background-color: #f0f9eb; color: #2d8a2e; border: 1px solid #c3e6cb; }
    
    /* CATEGORY TAGS */
    .tag-israel { background-color: #e8f4fd; color: #0056b3; border: 1px solid #badce3; }
    .tag-malware { background-color: #fce8e8; color: #c0392b; border: 1px solid #ebcccc; }
    
    /* LINKS */
    a { text-decoration: none; color: #0066cc !important; font-weight: bold; }
    a:hover { text-decoration: underline; }
    
    /* HEADER STATUS */
    .status-header {
        background-color: #f8f9fa;
        color: #333;
        padding: 12px 20px;
        border-radius: 10px;
        border: 1px solid #e9ecef;
        margin-bottom: 25px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        font-size: 0.95rem;
    }
</style>
""", unsafe_allow_html=True)

# --- INITIALIZE ---
# Auto-refresh every 15 minutes (adjustable)
REFRESH_MINUTES = 15
st_autorefresh(interval=REFRESH_MINUTES * 60 * 1000, key="auto_refresh")

# Initialize DB structure if not exists
init_db()

# Session State for Filters and Tools
if 'filter_type' not in st.session_state: st.session_state.filter_type = 'All'
if 'ioc_data' not in st.session_state: st.session_state.ioc_data = {}
if 'current_ioc' not in st.session_state: st.session_state.current_ioc = ""

# --- LOAD SECRETS ---
# Graceful error handling for missing secrets
try: 
    GEMINI_KEY = st.secrets.get("gemini_key", "")
    ABUSE_KEY = st.secrets.get("abuseipdb_key", "")
    VT_KEY = st.secrets.get("vt_key", "")
    URLSCAN_KEY = st.secrets.get("urlscan_key", "")
except:
    GEMINI_KEY = ""
    st.error("⚠️ Secrets not found! Please check .streamlit/secrets.toml")

# --- HELPERS ---
IL_TZ = pytz.timezone('Asia/Jerusalem')
def get_time_str(): return datetime.datetime.now(IL_TZ).strftime("%H:%M")
def get_next_update_str(): return (datetime.datetime.now(IL_TZ) + datetime.timedelta(minutes=REFRESH_MINUTES)).strftime("%H:%M")

# --- MAIN HEADER ---
st.title("🛡️ SOC War Room")
st.caption("Cyber Threat Intelligence Dashboard | Israel Focus")

# Status Bar
st.markdown(f"""
<div class="status-header">
    <span>📡 <b>System Status:</b> Online | <b>Auto-Refresh:</b> Every {REFRESH_MINUTES}m</span>
    <span>🕒 <b>Last Update:</b> {get_time_str()} | <b>Next:</b> {get_next_update_str()} (IL Time)</span>
</div>
""", unsafe_allow_html=True)

# --- SIDEBAR CONTROLS ---
with st.sidebar:
    st.header("⚙️ System Controls")
    
    # API Health Check
    with st.expander("API & Connectivity", expanded=True):
        ok, msg = ConnectionManager.check_gemini(GEMINI_KEY)
        st.write(f"{'✅' if ok else '❌'} **AI Brain:** {msg}")
        st.write(f"{'✅' if VT_KEY else '⚠️'} **VirusTotal**")
        st.write(f"{'✅' if URLSCAN_KEY else '⚠️'} **URLScan**")
        if not GEMINI_KEY:
            st.warning("Please add 'gemini_key' to secrets.")
    
    st.divider()
    
    # MANUAL UPDATE BUTTON
    if st.button("🚀 Force Global Update", type="primary", help="Scans all sources for NEW items only"):
        with st.status("🔄 Executing Cyber Intelligence Cycle...", expanded=True) as status:
            async def run_update():
                col = CTICollector()
                proc = AIBatchProcessor(GEMINI_KEY)
                
                st.write("1. Scanning Feeds (Gov.il, Calcalist, Unit42...)...")
                # This now checks for duplicates inside utils.py
                raw_items = await col.get_all_data()
                
                if not raw_items:
                    st.write("✅ No new items found in feeds.")
                    return 0
                
                st.write(f"2. Found {len(raw_items)} NEW items. Sending to AI...")
                analyzed_items = await proc.analyze_batch(raw_items)
                
                st.write("3. Saving to Database...")
                count = save_reports(raw_items, analyzed_items)
                return count

            # Run Async Loop
            try:
                new_count = asyncio.run(run_update())
                status.update(label=f"Done! Added {new_count} new reports.", state="complete", expanded=False)
                if new_count > 0:
                    st.rerun() # Refresh page to show new data
            except Exception as e:
                st.error(f"Update Failed: {e}")

    st.markdown("---")
    st.info("**Note:** 'Force Update' only fetches articles not yet in the DB to save AI quotas.")

# --- TABS LAYOUT ---
tab_feed, tab_tools, tab_strat, tab_map = st.tabs(["🔴 Live Feed", "🛠️ SOC Toolbox", "🧠 Strategic Intel", "🌍 Global Map"])

# ==========================================
# TAB 1: LIVE FEED
# ==========================================
with tab_feed:
    # 1. Fetch Data
    conn = sqlite3.connect(DB_NAME)
    # Get latest 100 reports
    df = pd.read_sql_query("SELECT * FROM intel_reports ORDER BY published_at DESC LIMIT 100", conn)
    conn.close()

    # 2. Filter Logic
    c1, c2, c3, c4 = st.columns(4)
    
    # Calculate counters
    count_crit = len(df[df['severity'].str.contains('Critical', case=False, na=False)])
    count_il = len(df[df['category'].str.contains('Israel', case=False, na=False)])
    count_mal = len(df[df['category'].str.contains('Malware', case=False, na=False)])
    
    # Filter Buttons
    if c1.button(f"🚨 Critical ({count_crit})", use_container_width=True): st.session_state.filter_type = 'Critical'
    if c2.button(f"🇮🇱 Israel Focus ({count_il})", use_container_width=True): st.session_state.filter_type = 'Israel'
    if c3.button(f"🦠 Malware ({count_mal})", use_container_width=True): st.session_state.filter_type = 'Malware'
    if c4.button(f"🌐 All Reports ({len(df)})", use_container_width=True): st.session_state.filter_type = 'All'

    # Apply Filter
    view_df = df
    if st.session_state.filter_type == 'Critical': view_df = df[df['severity'].str.contains('Critical', case=False, na=False)]
    elif st.session_state.filter_type == 'Israel': view_df = df[df['category'].str.contains('Israel', case=False, na=False)]
    elif st.session_state.filter_type == 'Malware': view_df = df[df['category'].str.contains('Malware', case=False, na=False)]

    st.divider()

    # 3. Render Cards
    if view_df.empty:
        st.info(f"No active reports found for category: {st.session_state.filter_type}")
    else:
        for index, row in view_df.iterrows():
            # Date Formatting
            try:
                # We expect ISO format from utils.py
                dt_obj = parser.parse(row['published_at'])
                # Ensure timezone
                if dt_obj.tzinfo is None: dt_obj = pytz.utc.localize(dt_obj)
                dt_il = dt_obj.astimezone(IL_TZ)
                display_date = dt_il.strftime("%d/%m %H:%M")
            except:
                display_date = str(row['published_at'])[:16]

            # Style Logic
            sev = row['severity'] if row['severity'] else "Medium"
            cat = row['category'] if row['category'] else "General"
            
            # Border Color Mapping
            bord_color = "#444"
            sev_class = "tag-medium"
            
            if "Critical" in sev: 
                bord_color = "#cc0000"
                sev_class = "tag-critical"
            elif "High" in sev: 
                bord_color = "#ff8800"
                sev_class = "tag-high"
            elif "Low" in sev:
                sev_class = "tag-low"

            cat_class = "tag-israel" if "Israel" in cat else "tag-medium"

            # HTML Card
            st.markdown(f"""
            <div class="report-card" style="border-left: 6px solid {bord_color};">
                <div style="margin-bottom:12px;">
                    <span class="tag tag-time">{display_date}</span>
                    <span class="tag {sev_class}">{sev}</span>
                    <span class="tag {cat_class}">{cat}</span>
                </div>
                <div class="card-title">{row['title']}</div>
                <div class="card-summary">{row['summary']}</div>
                <div class="card-meta">
                    <span><b>Source:</b> {row['source']}</span>
                    <a href="{row['url']}" target="_blank">Read Original Report ↗</a>
                </div>
            </div>""", unsafe_allow_html=True)

# ==========================================
# TAB 2: SOC TOOLBOX
# ==========================================
with tab_tools:
    st.markdown("### 🛠️ Analyst Investigation Suite")
    st.caption("Enrich IOCs using configured API keys.")
    
    col_input, col_btn = st.columns([4,1])
    ioc_input = col_input.text_input("Enter Indicator (IP, Domain, URL, Hash)", placeholder="e.g., 1.1.1.1 or malicious-site.com")
    
    if col_btn.button("🔍 Scan IOC", use_container_width=True):
        if ioc_input:
            st.session_state.current_ioc = ioc_input
            st.session_state.ioc_data = {} # Reset
            
            with st.status("Querying Threat Intelligence Engines...", expanded=True) as status:
                tl = ThreatLookup(vt_key=VT_KEY, urlscan_key=URLSCAN_KEY, abuse_ch_key="")
                
                # Parallel Execution isn't strictly necessary for UI feel here, sequential is safer for rate limits
                st.write("Checking VirusTotal...")
                vt_res = tl.query_virustotal(ioc_input)
                
                st.write("Checking URLScan.io...")
                us_res = tl.query_urlscan(ioc_input)

                st.write("Checking AbuseIPDB & ThreatFox...")
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc_input):
                    ab_res = tl.query_abuseipdb(ioc_input, ABUSE_KEY)
                else: ab_res = {"status": "skipped"}
                
                tf_res = tl.query_threatfox(ioc_input)
                uh_res = tl.query_urlhaus(ioc_input)
                
                # Save to session
                st.session_state.ioc_data = {
                    "virustotal": vt_res, 
                    "urlscan": us_res, 
                    "abuseipdb": ab_res, 
                    "threatfox": tf_res, 
                    "urlhaus": uh_res
                }
                status.update(label="Scan Complete!", state="complete", expanded=False)

    # Display Results if data exists
    if st.session_state.ioc_data:
        st.divider()
        st.subheader(f"📊 Results for: `{st.session_state.current_ioc}`")
        
        t1, t2, t3, t4 = st.tabs(["VirusTotal", "URLScan", "Reputation DBs", "AI Verdict"])
        
        with t1:
            d = st.session_state.ioc_data.get('virustotal', {})
            if d.get('status') == 'found':
                c1, c2, c3 = st.columns(3)
                c1.metric("Malicious", d['stats']['malicious'])
                c2.metric("Suspicious", d['stats']['suspicious'])
                c3.metric("Reputation Score", d.get('reputation', 0))
                st.json(d['stats'])
            else: st.info(d.get('msg', 'Not Found in VirusTotal'))

        with t2:
            d = st.session_state.ioc_data.get('urlscan', {})
            if d.get('status') == 'found':
                verdict = (d.get('verdict') or {}).get('overall', 'Unknown')
                st.write(f"**Verdict:** {verdict}")
                if d.get('screenshot'): st.image(d['screenshot'], caption="Live Screenshot", use_column_width=True)
                if d.get('page'): st.write(f"**Target URL:** {d['page'].get('url')}")
            else: st.info(d.get('msg', 'Not Found in URLScan'))

        with t3:
            c1, c2 = st.columns(2)
            with c1:
                st.markdown("**AbuseIPDB**")
                d = st.session_state.ioc_data.get('abuseipdb', {})
                if d.get('success'):
                    st.metric("Confidence Score", d['data']['abuseConfidenceScore'])
                    st.write(f"ISP: {d['data']['isp']}")
                    st.write(f"Country: {d['data']['countryCode']}")
                else: st.write("No Data")
            
            with c2:
                st.markdown("**ThreatFox / URLHaus**")
                tf = st.session_state.ioc_data.get('threatfox', {})
                st.write(f"ThreatFox: {tf.get('status')}")

        with t4:
            st.markdown("#### 🤖 AI Analyst Assessment")
            if st.button("Generate AI Report", key="gen_ai_ioc"):
                with st.spinner("AI is analyzing technical data..."):
                    proc = AIBatchProcessor(GEMINI_KEY)
                    # Run async function in sync context
                    rep = asyncio.run(proc.analyze_single_ioc(st.session_state.current_ioc, st.session_state.ioc_data))
                    st.markdown(rep)

# ==========================================
# TAB 3: STRATEGIC INTEL
# ==========================================
with tab_strat:
    st.subheader("🧠 Threat Actor Tracking")
    st.markdown("Monitoring known APT groups targeting Israel and the Middle East.")
    
    col = APTSheetCollector()
    threats = col.fetch_threats()
    
    # Check "Active" Status by searching DB
    conn = sqlite3.connect(DB_NAME)
    all_text = pd.read_sql_query("SELECT title, summary FROM intel_reports", conn).to_string().lower()
    conn.close()

    # Grid Layout
    cols = st.columns(3)
    for i, actor in enumerate(threats):
        # Simple string match to check if actor was mentioned recently
        is_active = actor['name'].lower() in all_text
        
        with cols[i % 3]:
            with st.container(border=True):
                # Header with Status
                status_icon = "🔴" if is_active else "⚪"
                status_text = "RECENTLY ACTIVE" if is_active else "Monitoring"
                
                st.markdown(f"### {actor['origin']} {actor['name']}")
                st.caption(f"{status_icon} {status_text} | {actor['type']}")
                
                st.markdown(f"**Target:** {actor['target']}")
                st.markdown(f"**Tools:** `{actor['tools']}`")
                st.markdown(f"_{actor['desc']}_")
                
                st.divider()
                
                if st.button(f"🏹 Hunt for {actor['name']}", key=f"hunt_{i}"):
                    with st.spinner(f"Generating Hunting Queries (YARA/XQL)..."):
                        proc = AIBatchProcessor(GEMINI_KEY)
                        context = "Recent news mentions found." if is_active else "Standard TTPs."
                        rules = asyncio.run(proc.generate_hunting_queries(actor, context))
                        
                        # Show result in a nice expander
                        with st.expander("View Detection Logic", expanded=True):
                            st.markdown(rules)

# ==========================================
# TAB 4: GLOBAL MAP
# ==========================================
with tab_map:
    st.subheader("🌍 Live Cyber Threat Map")
    st.caption("Real-time visualization of global attacks (Source: Check Point ThreatCloud).")
    
    # CheckPoint Map Iframe
    components.iframe("https://threatmap.checkpoint.com/", height=600, scrolling=False)
    
    st.divider()
    
    c1, c2 = st.columns([1, 4])
    if c1.button("🤖 Analyze Global Trends"):
        with st.spinner("Reading latest global headlines..."):
            conn = sqlite3.connect(DB_NAME)
            # Get latest 20 titles to summarize trends
            df_map = pd.read_sql_query("SELECT title, source FROM intel_reports ORDER BY published_at DESC LIMIT 20", conn)
            conn.close()
            
            prompt = f"Based on these headers, what are the top 3 global threat trends right now? Keep it short. Data: {df_map.to_string()}"
            proc = AIBatchProcessor(GEMINI_KEY)
            res = asyncio.run(query_gemini_auto(GEMINI_KEY, prompt))
            st.markdown(f"### 🌐 AI Situation Report\n{res}")
