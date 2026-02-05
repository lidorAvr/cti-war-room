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

# --- UI STYLING (BALANCED PRO & VISIBILITY) ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Heebo:wght@300;400;700&display=swap');
    
    /* 1. BALANCED TEXT SIZES */
    html, body, [class*="css"] {
        font-family: 'Heebo', sans-serif;
        font-size: 17px; /* Optimal size for readability without breaking layout */
    }
    
    p, .stMarkdown, span, div {
        color: #e6edf3;
        line-height: 1.5;
    }

    /* Headers */
    h1 { font-size: 2.5rem !important; margin-bottom: 0 !important; }
    h2 { font-size: 2rem !important; }
    h3 { font-size: 1.5rem !important; }
    
    h1, h2, h3 { 
        font-family: 'JetBrains Mono', monospace; 
        color: #00f2ff !important; 
        text-shadow: 0 0 10px rgba(0, 242, 255, 0.3); 
    }
    
    /* 2. INPUT FIELDS & PLACEHOLDER FIX */
    /* The Input Field Itself */
    input[type="text"] {
        background-color: #0d1117 !important;
        color: #00f2ff !important; /* Text color when typing */
        border: 1px solid #30363d !important;
        font-family: 'JetBrains Mono', monospace;
    }
    
    /* The Placeholder Text (The fix you asked for) */
    input::placeholder {
        color: #8b949e !important;
        opacity: 1; /* Firefox */
    }
    input::-ms-input-placeholder { color: #8b949e !important; }
    
    /* 3. BUTTON STYLING */
    div.stButton > button {
        background-color: transparent !important;
        border: 1px solid #00f2ff !important;
        color: #00f2ff !important;
        border-radius: 6px;
        font-family: 'JetBrains Mono', monospace;
        transition: all 0.3s ease;
    }
    div.stButton > button:hover {
        background-color: rgba(0, 242, 255, 0.1) !important;
        box-shadow: 0 0 10px rgba(0, 242, 255, 0.4);
    }
    /* Primary Action Button */
    div.stButton > button[kind="primary"] {
        border-color: #ff7b72 !important;
        color: #ff7b72 !important;
    }
    div.stButton > button[kind="primary"]:hover {
        background-color: rgba(255, 123, 114, 0.1) !important;
        box-shadow: 0 0 10px rgba(255, 123, 114, 0.4);
    }

    /* 4. TAGS & RADIO BUTTONS */
    div[role="radiogroup"] label {
        background-color: #161b22 !important;
        border: 1px solid #30363d !important;
        color: #e6edf3 !important;
        padding: 6px 14px !important;
        border-radius: 6px;
    }
    div[role="radiogroup"] label[data-checked="true"] {
        background-color: #1f6feb !important;
        border-color: #1f6feb !important;
        color: white !important;
    }

    /* 5. CARDS */
    .report-card { 
        background-color: #161b22; 
        padding: 15px 20px; 
        border-radius: 8px; 
        border: 1px solid #30363d;
        margin-bottom: 12px; 
    }
    
    /* Metric Values */
    div[data-testid="stMetricValue"] {
        font-size: 2rem !important;
        color: #00f2ff !important;
        font-family: 'JetBrains Mono', monospace;
    }

    /* INCD/Global Styles */
    .card-incd {
        border-right: 4px solid #2f81f7;
        direction: rtl; text-align: right;
        background: linear-gradient(90deg, #161b22 0%, #1c2128 100%);
    }
    .incd-title { color: #a5d6ff !important; font-weight: bold; font-size: 1.2rem; }
    
    .card-global {
        border-left: 4px solid #3fb950;
        direction: ltr; text-align: left;
    }
    .global-title { color: #7ee787 !important; font-weight: bold; font-size: 1.2rem; }

    /* Links */
    a { color: #58a6ff !important; text-decoration: none; }
    a:hover { text-decoration: underline; }
    
    /* 6. CREDITS FOOTER */
    .footer {
        position: fixed;
        left: 0;
        bottom: 0;
        width: 100%;
        background-color: #0d1117;
        color: #8b949e;
        text-align: center;
        padding: 10px;
        border-top: 1px solid #30363d;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.8rem;
        z-index: 9999;
    }
    .footer a { color: #00f2ff !important; font-weight: bold; }
    
    /* CREDITS HEADER */
    .header-credit {
        text-align: center;
        font-family: 'JetBrains Mono', monospace;
        color: #484f58;
        font-size: 0.75rem;
        margin-top: -15px;
        margin-bottom: 20px;
        letter-spacing: 2px;
        text-transform: uppercase;
    }
</style>
""", unsafe_allow_html=True)

# --- INITIALIZATION ---
init_db() 
IL_TZ = pytz.timezone('Asia/Jerusalem')
REFRESH_MINUTES = 10
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

# --- SIDEBAR ---
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/9203/9203726.png", width=70)
    st.title("CTI WAR ROOM")
    st.markdown("`v4.0 | CLASSIFIED`")
    
    st.markdown("---")
    st.markdown("### 🛰️ System Status")
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
    st.progress(70) 
    st.caption("Current Alert Level: ELEVATED")

# --- MAIN LAYOUT ---

# 1. HEADER CREDIT
st.markdown('<div class="header-credit">SYSTEM ARCHITECT: LIDOR AVRAHAMY</div>', unsafe_allow_html=True)

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
with m1: st.metric("New Reports (24h)", count_24h)
with m2: st.metric("Critical Threats", count_crit, delta=f"+{count_crit}" if count_crit > 0 else "0", delta_color="inverse")
with m3: st.metric("Active Sources", "7", "Online")
with m4: st.metric("System Uptime", "99.9%", "Stable")

st.markdown("---")

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
        c_filter1, c_filter2 = st.columns([1, 1])
        with c_filter1:
            st.markdown("##### 🕵️ Data Source")
            filter_source = st.radio("Source", ["All Sources", "🇮🇱 INCD Only", "🌍 Global Only"], horizontal=True, label_visibility="collapsed")
        with c_filter2:
            st.markdown("##### 🚨 Severity Level")
            filter_sev = st.radio("Severity", ["All Levels", "🔥 Critical/High", "⚠️ Medium", "ℹ️ Info/Low"], horizontal=True, label_visibility="collapsed")

        df_display = df_final.copy()
        if "INCD" in filter_source: df_display = df_display[df_display['source'] == 'INCD']
        elif "Global" in filter_source: df_display = df_display[df_display['source'] != 'INCD']
        
        if "Critical" in filter_sev: df_display = df_display[df_display['severity'].str.contains('Critical|High', case=False, na=False)]
        elif "Medium" in filter_sev: df_display = df_display[df_display['severity'].str.contains('Medium', case=False, na=False)]
        elif "Info" in filter_sev: df_display = df_display[df_display['severity'].str.contains('Low|Info|News', case=False, na=False)]

        st.write("")
        
        for _, row in df_display.iterrows():
            try:
                dt = date_parser.parse(row['published_at'])
                if dt.tzinfo is None: dt = pytz.utc.localize(dt).astimezone(IL_TZ)
                else: dt = dt.astimezone(IL_TZ)
                date_str = dt.strftime('%H:%M | %d/%m')
            except: date_str = "--:--"

            is_incd = row['source'] == "INCD"
            card_class = "card-incd" if is_incd else "card-global"
            title_class = "incd-title" if is_incd else "global-title"
            
            # Severity Tag logic inline styling
            sev_tag_style = "background: rgba(88, 166, 255, 0.15); color: #58a6ff;"
            if "Critical" in row['severity'] or "High" in row['severity']:
                sev_tag_style = "background: rgba(255, 123, 114, 0.15); color: #ff7b72; border: 1px solid #ff7b72;"
            
            source_badge = "🇮🇱 מ. הסייבר" if is_incd else f"📡 {row['source']}"
            
            st.markdown(f"""
            <div class="report-card {card_class}">
                <div style="margin-bottom: 8px; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; {sev_tag_style}">{row['severity'].upper()}</span>
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
        btn_scan = st.button("🔍 INITIATE SCAN", type="primary", use_container_width=True)

    if btn_scan and ioc_input:
        ioc_type = identify_ioc_type(ioc_input)
        if not ioc_type:
            st.error("❌ INVALID FORMAT DETECTED")
        else:
            st.success(f"TARGET ACQUIRED: {ioc_type.upper()}")
            tl = ThreatLookup(VT_KEY, URLSCAN_KEY, ABUSE_KEY)
            
            with st.spinner("⚡ Querying Threat Intelligence Engines..."):
                vt_data = tl.query_virustotal(ioc_input, ioc_type)
                us_data = tl.query_urlscan(ioc_input) if ioc_type in ["domain", "url", "ip"] else None
                ab_data = tl.query_abuseipdb(ioc_input) if ioc_type == "ip" else None
                
                results_context = {"virustotal": vt_data, "urlscan": us_data, "abuseipdb": ab_data}
                proc = AIBatchProcessor(GROQ_KEY)
                ai_report = asyncio.run(proc.analyze_single_ioc(ioc_input, ioc_type, results_context))

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
                <div style="background-color: #0d1117; border: 1px solid #30363d; padding: 20px; border-radius: 8px; font-family: 'Heebo'; color: #e6edf3;">
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
        st.markdown(f"""
        <div style="border: 1px solid #30363d; border-radius: 8px; padding: 20px; background: #161b22;">
            <h2 style="margin-top:0; color: #f0f6fc !important; font-size: 2rem;">{actor['name']}</h2>
            <div style="display: flex; gap: 10px; margin-bottom: 15px;">
                <span style="background: rgba(88, 166, 255, 0.15); color: #58a6ff; padding: 4px 10px; border-radius: 4px;">ORIGIN: {actor['origin']}</span>
                <span style="background: rgba(210, 153, 34, 0.15); color: #d29922; padding: 4px 10px; border-radius: 4px;">TARGET: {actor['target']}</span>
            </div>
            <p style="color: #e6edf3; font-size: 1.1rem; line-height: 1.5;">{actor['desc']}</p>
            <hr style="border-color: #30363d;">
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
                <div>
                    <h5 style="color: #58a6ff !important;">🛠️ Toolset</h5>
                    <code style="background: #0d1117; color: #ff7b72; display: block; padding: 8px;">{actor['tools']}</code>
                </div>
                <div>
                    <h5 style="color: #58a6ff !important;">📚 MITRE TTPs</h5>
                    <code style="background: #0d1117; color: #d29922; display: block; padding: 8px;">{actor['mitre']}</code>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        if 'hunt_rules' in st.session_state:
            st.markdown("### 🛡️ Generated Detection Logic")
            st.code(st.session_state['hunt_rules'], language="sql")

# --- TAB 4: MAP ---
with tab_map:
    st.markdown("#### 🌍 Live Attack Map")
    components.iframe("https://threatmap.checkpoint.com/", height=700)

# --- FOOTER CREDIT ---
st.markdown("""
<div class="footer">
    DESIGNED & BUILT BY LIDOR AVRAHAMY | 
    <a href="https://www.linkedin.com/in/lidoravrahamy/" target="_blank">LINKEDIN PROFILE 🔗</a>
</div>
""", unsafe_allow_html=True)
