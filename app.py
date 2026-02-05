import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import datetime
import pytz
import streamlit.components.v1 as components
from utils import *
from dateutil import parser as date_parser
from streamlit_autorefresh import st_autorefresh

# --- CONFIGURATION ---
st.set_page_config(page_title="CTI WAR ROOM", layout="wide", page_icon="🛡️")

# --- UI STYLING (CYBER DARK MODE) ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Heebo:wght@300;400;700&display=swap');
    
    /* GLOBAL THEME */
    .stApp {
        background-color: #0e1117;
        color: #e0e0e0;
        font-family: 'Heebo', sans-serif;
    }
    
    h1, h2, h3 { font-family: 'JetBrains Mono', monospace; color: #00f2ff; }
    h4, h5, h6 { color: #b3b3b3; }
    
    /* CUSTOM SCROLLBAR */
    ::-webkit-scrollbar { width: 10px; }
    ::-webkit-scrollbar-track { background: #0e1117; }
    ::-webkit-scrollbar-thumb { background: #333; border-radius: 5px; }
    ::-webkit-scrollbar-thumb:hover { background: #00f2ff; }

    /* METRIC CARDS */
    div[data-testid="stMetricValue"] {
        color: #00f2ff !important;
        font-family: 'JetBrains Mono', monospace;
    }

    /* REPORT CARDS (General) */
    .report-card { 
        background-color: #161b22; 
        padding: 15px; 
        border-radius: 6px; 
        border: 1px solid #30363d;
        margin-bottom: 15px; 
        transition: transform 0.2s, box-shadow 0.2s;
    }
    .report-card:hover {
        border-color: #58a6ff;
        box-shadow: 0 4px 20px rgba(88, 166, 255, 0.1);
    }

    /* INCD CARDS (Hebrew / RTL) */
    .card-incd {
        border-right: 4px solid #2f81f7; /* Blue accent */
        direction: rtl;
        text-align: right;
        background: linear-gradient(90deg, #161b22 0%, #1c2128 100%);
    }
    .incd-title { color: #a5d6ff; font-weight: bold; font-size: 1.1rem; }
    
    /* GLOBAL CARDS (English / LTR) */
    .card-global {
        border-left: 4px solid #3fb950; /* Green accent */
        direction: ltr;
        text-align: left;
    }
    .global-title { color: #7ee787; font-weight: bold; font-size: 1.1rem; }
    
    /* SEVERITY TAGS & ANIMATION */
    .sev-tag {
        display: inline-block; padding: 2px 8px; border-radius: 4px; 
        font-size: 0.75rem; font-family: 'JetBrains Mono', monospace; font-weight: bold;
        margin: 0 5px;
    }
    
    .sev-critical { 
        background: rgba(255, 0, 0, 0.2); color: #ff7b72; border: 1px solid #ff7b72;
        animation: pulse 2s infinite;
    }
    
    @keyframes pulse {
        0% { box-shadow: 0 0 0 0 rgba(255, 123, 114, 0.4); }
        70% { box-shadow: 0 0 0 10px rgba(255, 123, 114, 0); }
        100% { box-shadow: 0 0 0 0 rgba(255, 123, 114, 0); }
    }

    .sev-high { background: rgba(210, 153, 34, 0.2); color: #d29922; border: 1px solid #d29922; }
    .sev-med { background: rgba(56, 139, 253, 0.2); color: #58a6ff; border: 1px solid #58a6ff; }
    .sev-info { background: rgba(139, 148, 158, 0.2); color: #8b949e; border: 1px solid #30363d; }

    /* LINKS */
    a { text-decoration: none; color: #58a6ff; transition: color 0.2s; }
    a:hover { color: #a5d6ff; text-decoration: underline; }

    /* RADIO BUTTONS AS TAGS */
    div[role="radiogroup"] { display: flex; gap: 10px; flex-wrap: wrap; }
    div[role="radiogroup"] label {
        background-color: #21262d !important;
        border: 1px solid #30363d;
        color: #c9d1d9 !important;
        border-radius: 20px;
        padding: 5px 15px;
        font-size: 0.9rem;
    }
    div[role="radiogroup"] label[data-checked="true"] {
        background-color: #1f6feb !important;
        border-color: #1f6feb;
        color: white !important;
        box-shadow: 0 0 10px rgba(31, 111, 235, 0.5);
    }
    
    /* TOOLBOX STYLES */
    .toolbox-input input {
        background-color: #0d1117;
        color: #00f2ff;
        border: 1px solid #30363d;
        font-family: 'JetBrains Mono', monospace;
    }
</style>
""", unsafe_allow_html=True)

# --- INITIALIZATION ---
init_db() 
IL_TZ = pytz.timezone('Asia/Jerusalem')
REFRESH_MINUTES = 10

# --- AUTO-REFRESH COMPONENT ---
st_autorefresh(interval=REFRESH_MINUTES * 60 * 1000, key="data_refresh")

GROQ_KEY = st.secrets.get("groq_key", "")
VT_KEY = st.secrets.get("vt_key", "")
URLSCAN_KEY = st.secrets.get("urlscan_key", "")
ABUSE_KEY = st.secrets.get("abuseipdb_key", "")

# --- UPDATE LOGIC ---
async def perform_update():
    col, proc = CTICollector(), AIBatchProcessor(GROQ_KEY)
    raw = await col.get_all_data()
    if raw:
        analyzed = await proc.analyze_batch(raw)
        return save_reports(raw, analyzed)
    return 0

# --- AUTO-LOAD CHECK ---
if "last_run" not in st.session_state:
    st.session_state["last_run"] = datetime.datetime.now(IL_TZ)
    with st.spinner("📡 ESTABLISHING UPLINK..."):
        asyncio.run(perform_update())
else:
    now = datetime.datetime.now(IL_TZ)
    last_run = st.session_state["last_run"]
    if (now - last_run).total_seconds() > (REFRESH_MINUTES * 60):
        with st.empty():
            st.info("🔄 SYNCING INTEL FEEDS...")
            asyncio.run(perform_update())
            st.session_state["last_run"] = now

# --- SIDEBAR (COMMAND CENTER) ---
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/9203/9203726.png", width=70)
    st.title("CTI WAR ROOM")
    st.markdown("`v2.0 | CLASSIFIED`")
    
    st.markdown("---")
    st.markdown("### 🛰️ System Status")
    
    # Live Status Indicators
    ok, msg = ConnectionManager.check_groq(GROQ_KEY)
    col_s1, col_s2 = st.columns([1, 4])
    with col_s1: st.markdown("🟢" if ok else "🔴")
    with col_s2: st.caption(f"AI Engine: {msg}")
    
    st.markdown("---")
    if st.button("⚡ FORCE SYNC", type="primary", use_container_width=True):
        with st.status("Executing Global Scan...", expanded=True):
            count = asyncio.run(perform_update())
            st.session_state["last_run"] = datetime.datetime.now(IL_TZ)
            st.success(f"Intel Updated: {count} new items")
            st.rerun()

    st.markdown("### 🛡️ Defcon Level")
    st.progress(70) # Static for visual effect
    st.caption("Current Alert Level: ELEVATED")

# --- MAIN LAYOUT ---
st.title("📟 OPERATIONAL DASHBOARD")

# Top Metrics
conn = sqlite3.connect(DB_NAME)
c = conn.cursor()
c.execute("SELECT COUNT(*) FROM intel_reports WHERE published_at > datetime('now', '-24 hours')")
count_24h = c.fetchone()[0]
c.execute("SELECT COUNT(*) FROM intel_reports WHERE severity LIKE '%Critical%' AND published_at > datetime('now', '-24 hours')")
count_crit = c.fetchone()[0]
conn.close()

m1, m2, m3, m4 = st.columns(4)
with m1: st.metric("New Reports (24h)", count_24h, delta_color="normal")
with m2: st.metric("Critical Threats", count_crit, delta=f"+{count_crit}" if count_crit > 0 else "0", delta_color="inverse")
with m3: st.metric("Active Sources", "7", "Online")
with m4: st.metric("System Uptime", "99.9%", "Stable")

st.markdown("---")

# Tabs
tab_feed, tab_tools, tab_strat, tab_map = st.tabs(["🔴 LIVE FEED", "🛠️ INVESTIGATION LAB", "🧠 THREAT PROFILER", "🌍 GLOBAL HEATMAP"])

# --- TAB 1: LIVE FEED ---
with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    df_incd = pd.read_sql_query("SELECT * FROM intel_reports WHERE source = 'INCD' ORDER BY published_at DESC LIMIT 15", conn)
    df_others = pd.read_sql_query("SELECT * FROM intel_reports WHERE source != 'INCD' AND published_at > datetime('now', '-2 days') ORDER BY published_at DESC LIMIT 50", conn)
    conn.close()
    
    df_final = pd.concat([df_incd, df_others]).sort_values(by='published_at', ascending=False).drop_duplicates(subset=['url'])
    
    if df_final.empty:
        st.info("No active threats found. Systems Clear.")
    else:
        # Filters
        c_filter1, c_filter2 = st.columns([1, 1])
        with c_filter1:
            st.markdown("##### 🕵️ Data Source")
            filter_source = st.radio("Source", ["All Sources", "🇮🇱 INCD Only", "🌍 Global Only"], horizontal=True, label_visibility="collapsed")
        with c_filter2:
            st.markdown("##### 🚨 Severity Level")
            filter_sev = st.radio("Severity", ["All Levels", "🔥 Critical/High", "⚠️ Medium", "ℹ️ Info/Low"], horizontal=True, label_visibility="collapsed")

        # Apply Logic
        df_display = df_final.copy()
        if "INCD" in filter_source: df_display = df_display[df_display['source'] == 'INCD']
        elif "Global" in filter_source: df_display = df_display[df_display['source'] != 'INCD']
        
        if "Critical" in filter_sev: df_display = df_display[df_display['severity'].str.contains('Critical|High', case=False, na=False)]
        elif "Medium" in filter_sev: df_display = df_display[df_display['severity'].str.contains('Medium', case=False, na=False)]
        elif "Info" in filter_sev: df_display = df_display[df_display['severity'].str.contains('Low|Info|News', case=False, na=False)]

        st.write("")
        
        # Render Feed
        for _, row in df_display.iterrows():
            # Date Parsing
            try:
                dt = date_parser.parse(row['published_at'])
                if dt.tzinfo is None: dt = pytz.utc.localize(dt).astimezone(IL_TZ)
                else: dt = dt.astimezone(IL_TZ)
                date_str = dt.strftime('%H:%M | %d/%m')
            except: date_str = "--:--"

            # Classes
            is_incd = row['source'] == "INCD"
            card_class = "card-incd" if is_incd else "card-global"
            title_class = "incd-title" if is_incd else "global-title"
            
            sev_lower = row['severity'].lower()
            if "critical" in sev_lower or "high" in sev_lower: sev_class = "sev-critical"
            elif "medium" in sev_lower: sev_class = "sev-med"
            elif "low" in sev_lower or "info" in sev_lower: sev_class = "sev-info"
            else: sev_class = "sev-high"

            # Content Logic
            source_badge = "🇮🇱 מ. הסייבר" if is_incd else f"📡 {row['source']}"
            
            # HTML Card
            st.markdown(f"""
            <div class="report-card {card_class}">
                <div style="margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span class="sev-tag {sev_class}">{row['severity'].upper()}</span>
                        <span style="font-size: 0.8rem; color: #8b949e; margin: 0 5px;">{row['category']}</span>
                    </div>
                    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; color: #8b949e;">
                        {date_str} • <b>{source_badge}</b>
                    </div>
                </div>
                <div class="{title_class}">{row['title']}</div>
                <div style="margin-top: 8px; color: #c9d1d9; font-size: 0.95rem; line-height: 1.5;">
                    {row['summary']}
                </div>
                <div style="margin-top: 12px; text-align: {'left' if not is_incd else 'right'};">
                    <a href="{row['url']}" target="_blank">🔗 SOURCE LINK</a>
                </div>
            </div>
            """, unsafe_allow_html=True)

# --- TAB 2: SOC TOOLBOX ---
with tab_tools:
    st.markdown("#### 🔬 IOC Forensic Analysis")
    
    col_input, col_action = st.columns([3, 1])
    with col_input:
        ioc_input = st.text_input("IOC Input", placeholder="IP, Domain, Hash, or URL...", label_visibility="collapsed")
    with col_action:
        btn_scan = st.button("🔍 INITIATE SCAN", use_container_width=True, type="primary")

    if btn_scan and ioc_input:
        ioc_type = identify_ioc_type(ioc_input)
        if not ioc_type:
            st.error("❌ INVALID FORMAT DETECTED")
        else:
            st.success(f"TARGET ACQUIRED: {ioc_type.upper()}")
            tl = ThreatLookup(VT_KEY, URLSCAN_KEY, ABUSE_KEY)
            
            # Use columns for layout
            with st.spinner("⚡ Querying Threat Intelligence Engines..."):
                vt_data = tl.query_virustotal(ioc_input, ioc_type)
                us_data = tl.query_urlscan(ioc_input) if ioc_type in ["domain", "url", "ip"] else None
                ab_data = tl.query_abuseipdb(ioc_input) if ioc_type == "ip" else None
                
                # Combine for AI
                results_context = {"virustotal": vt_data, "urlscan": us_data, "abuseipdb": ab_data}
                
                # AI Analysis
                proc = AIBatchProcessor(GROQ_KEY)
                ai_report = asyncio.run(proc.analyze_single_ioc(ioc_input, ioc_type, results_context))

            # Display Results
            c_res, c_ai = st.columns([1, 1])
            
            with c_res:
                st.markdown("### 📊 Raw Telemetry")
                with st.expander("🦠 VirusTotal Data", expanded=True):
                    if vt_data:
                        stats = vt_data.get('attributes', {}).get('last_analysis_stats', {})
                        mal = stats.get('malicious', 0)
                        color = "red" if mal > 0 else "green"
                        st.markdown(f":{color}[**Detections: {mal}/{sum(stats.values())}**]")
                        st.json(stats)
                    else: st.write("No Data Available")
                
                with st.expander("🛑 AbuseIPDB / URLScan"):
                    if ab_data: 
                        st.metric("Abuse Confidence", f"{ab_data.get('abuseConfidenceScore', 0)}%")
                        st.write(f"ISP: {ab_data.get('isp')}")
                    if us_data:
                        st.write(f"Verdict: {us_data.get('verdict', {}).get('overall')}")
                        if us_data.get('task', {}).get('screenshotURL'):
                            st.image(us_data['task']['screenshotURL'])

            with c_ai:
                st.markdown("### 🤖 AI Analyst Verdict")
                st.markdown(f"""
                <div style="background-color: #0d1117; border: 1px solid #30363d; padding: 20px; border-radius: 8px; font-family: 'Heebo';">
                    {ai_report}
                </div>
                """, unsafe_allow_html=True)

# --- TAB 3: STRATEGIC INTEL ---
with tab_strat:
    st.markdown("#### 🏴‍☠️ Adversary Profiling")
    
    threats = APTSheetCollector().fetch_threats()
    names = [t['name'] for t in threats]
    
    col_sel, col_info = st.columns([1, 3])
    
    with col_sel:
        st.markdown("**Select Target:**")
        selected = st.radio("APT Group", names, label_visibility="collapsed")
        actor = next(t for t in threats if t['name'] == selected)
        
        st.markdown("---")
        if st.button("🏹 Gen. Hunting Rules"):
            with st.spinner("Generating XQL/YARA..."):
                proc = AIBatchProcessor(GROQ_KEY)
                rules = asyncio.run(proc.generate_hunting_queries(actor))
                st.session_state['hunt_rules'] = rules

    with col_info:
        # DOSSIER UI
        st.markdown(f"""
        <div style="border: 1px solid #30363d; border-radius: 8px; padding: 20px; background: #161b22;">
            <h2 style="margin-top:0; color: #f0f6fc;">{actor['name']}</h2>
            <div style="display: flex; gap: 10px; margin-bottom: 15px;">
                <span class="sev-tag sev-med">ORIGIN: {actor['origin']}</span>
                <span class="sev-tag sev-high">TARGET: {actor['target']}</span>
                <span class="sev-tag sev-info">TYPE: {actor['type']}</span>
            </div>
            <p style="color: #c9d1d9;">{actor['desc']}</p>
            <hr style="border-color: #30363d;">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <div>
                    <h5 style="color: #58a6ff;">🛠️ Toolset</h5>
                    <code style="background: #0d1117; color: #ff7b72;">{actor['tools']}</code>
                </div>
                <div>
                    <h5 style="color: #58a6ff;">📚 MITRE TTPs</h5>
                    <code style="background: #0d1117; color: #d29922;">{actor['mitre']}</code>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        # SHOW RULES IF GENERATED
        if 'hunt_rules' in st.session_state:
            st.markdown("### 🛡️ Generated Detection Logic")
            st.code(st.session_state['hunt_rules'], language="sql")

# --- TAB 4: MAP ---
with tab_map:
    st.markdown("#### 🌍 Live Attack Map")
    components.iframe("https://threatmap.checkpoint.com/", height=700)
