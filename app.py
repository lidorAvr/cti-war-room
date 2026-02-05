import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import datetime
import pytz
import time
import textwrap
from utils import *
from dateutil import parser as date_parser

# --- CONFIGURATION ---
st.set_page_config(page_title="CTI WAR ROOM", layout="wide", page_icon="🛡️")

# --- HTML GENERATORS (FIXED: PREVENTS INDENTATION BUGS) ---
def get_status_html(ok, msg):
    color = "#4ade80" if ok else "#f87171"
    status = "ONLINE" if ok else "OFFLINE"
    return f"""
    <div style="display: flex; align-items: center; justify-content: space-between; background: #1e293b; padding: 10px; border-radius: 8px; margin-bottom: 10px; border: 1px solid #334155;">
        <span style="font-size: 0.9rem; color: #cbd5e1; font-family: 'Inter', sans-serif;">AI Engine</span>
        <span style="font-size: 0.8rem; color: {color}; font-weight: bold; font-family: 'JetBrains Mono', monospace; letter-spacing: 1px;">● {status}</span>
    </div>
    """

def get_feed_card_html(row, date_str):
    is_incd = row['source'] == "INCD"
    card_class = "card-incd" if is_incd else "card-global"
    
    # Severity Badge Logic
    sev = row['severity'].lower()
    badge_bg = "rgba(100, 116, 139, 0.2)"
    badge_color = "#cbd5e1"
    border_color = "rgba(100, 116, 139, 0.3)"
    
    if "critical" in sev or "high" in sev:
        badge_bg = "rgba(220, 38, 38, 0.2)"
        badge_color = "#fca5a5"
        border_color = "#ef4444"
    elif "medium" in sev:
        badge_bg = "rgba(59, 130, 246, 0.2)"
        badge_color = "#93c5fd"
        border_color = "#3b82f6"
        
    source_display = "🇮🇱 מ. הסייבר" if is_incd else f"📡 {row['source']}"
    align = 'right' if is_incd else 'left'
    dir = 'rtl' if is_incd else 'ltr'
    
    return f"""
    <div class="report-card {card_class}" style="direction: {dir};">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <div class="card-meta">
                {date_str} • <b style="color: #e2e8f0;">{source_display}</b>
            </div>
            <div style="background: {badge_bg}; color: {badge_color}; border: 1px solid {border_color}; padding: 2px 10px; border-radius: 99px; font-size: 0.75rem; font-weight: bold; letter-spacing: 0.5px;">
                {row['severity'].upper()}
            </div>
        </div>
        <div class="card-title">{row['title']}</div>
        <div style="font-size: 0.95rem; color: #cbd5e1; margin-bottom: 15px; line-height: 1.6; opacity: 0.9;">
            {row['summary']}
        </div>
        <div style="text-align: {align};">
            <a href="{row['url']}" target="_blank" style="display: inline-flex; align-items: center; gap: 5px; color: #38bdf8; text-decoration: none; font-size: 0.85rem; font-weight: 600; padding: 5px 10px; background: rgba(56, 189, 248, 0.1); border-radius: 6px; transition: all 0.2s;">
                OPEN REPORT 🔗
            </a>
        </div>
    </div>
    """

def get_dossier_html(actor):
    return f"""
    <div class="report-card" style="border-left: 4px solid #f59e0b; background: linear-gradient(180deg, rgba(30, 41, 59, 0.6) 0%, rgba(15, 23, 42, 0.8) 100%);">
        <h2 style="margin-top:0; color: #ffffff; font-size: 2rem; letter-spacing: -1px;">{actor['name']}</h2>
        <div style="margin-bottom: 25px; display: flex; gap: 10px; flex-wrap: wrap;">
            <span class="badge b-med">ORIGIN: {actor['origin']}</span>
            <span class="badge b-high">TARGET: {actor['target']}</span>
            <span class="badge b-low">TYPE: {actor['type']}</span>
        </div>
        <p style="font-size: 1.1rem; color: #e2e8f0; margin-bottom: 30px; line-height: 1.7; border-bottom: 1px solid #334155; padding-bottom: 20px;">
            {actor['desc']}
        </p>
        
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div style="background: rgba(15, 23, 42, 0.5); padding: 15px; border-radius: 8px; border: 1px solid #334155;">
                <h5 style="color: #94a3b8; margin-top: 0; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px;">🛠️ Known Tools</h5>
                <code style="color: #fca5a5; background: transparent; font-size: 0.95rem;">{actor['tools']}</code>
            </div>
            <div style="background: rgba(15, 23, 42, 0.5); padding: 15px; border-radius: 8px; border: 1px solid #334155;">
                <h5 style="color: #94a3b8; margin-top: 0; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px;">📚 MITRE TTPs</h5>
                <code style="color: #fcd34d; background: transparent; font-size: 0.95rem;">{actor['mitre']}</code>
            </div>
        </div>
    </div>
    """

# --- CYBER BOOT SEQUENCE (LOADING SCREEN) ---
if 'booted' not in st.session_state:
    st.markdown("""
    <style>
        .stApp { background-color: #000000; }
        .boot-text { font-family: 'JetBrains Mono', monospace; color: #00f2ff; font-size: 1rem; }
    </style>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.write("")
        st.write("")
        st.write("")
        st.image("https://cdn-icons-png.flaticon.com/512/9203/9203726.png", width=100)
        st.markdown("<h3 style='text-align: center; color: #ffffff; font-family: monospace; letter-spacing: 2px;'>SYSTEM INITIALIZATION</h3>", unsafe_allow_html=True)
        
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        steps = [
            "Encrypting Uplink...",
            "Connecting to Threat Feeds...",
            "Syncing INCD Database...",
            "Loading AI Models (Llama-3)...",
            "Access Granted."
        ]
        
        for i, step in enumerate(steps):
            status_text.markdown(f"<div class='boot-text' style='text-align: center;'>{step}</div>", unsafe_allow_html=True)
            for p in range(20):
                time.sleep(0.01)
                progress_bar.progress(min((i * 20) + p, 100))
        
        progress_bar.progress(100)
        time.sleep(0.8)
        st.session_state['booted'] = True
        st.rerun()

# --- UI STYLING (GLOBAL CSS) ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&family=JetBrains+Mono:wght@400;700&family=Heebo:wght@300;400;700&display=swap');
    
    /* RESET & BASE THEME */
    .stApp {
        background-color: #0b0f19;
        background-image: radial-gradient(circle at 50% 0%, #1c2541 0%, #0b0f19 50%);
        font-family: 'Heebo', sans-serif;
    }
    
    h1, h2, h3 {
        font-family: 'Inter', sans-serif;
        font-weight: 600;
        letter-spacing: -0.5px;
        color: #ffffff !important;
    }
    
    p, div, span {
        color: #cbd5e1;
        line-height: 1.6;
    }

    /* GLASSMORPHISM CARDS */
    .report-card {
        background: rgba(30, 41, 59, 0.4);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid rgba(148, 163, 184, 0.1);
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 20px;
        transition: transform 0.2s;
    }
    .report-card:hover {
        border-color: rgba(56, 189, 248, 0.3);
        transform: translateY(-2px);
    }
    .card-incd { border-right: 4px solid #3b82f6; }
    .card-global { border-left: 4px solid #10b981; }

    .card-title {
        font-size: 1.25rem;
        font-weight: 700;
        color: #f1f5f9;
        margin-bottom: 12px;
    }
    
    .card-meta {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.85rem;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    /* BADGES */
    .badge {
        display: inline-flex;
        align-items: center;
        padding: 4px 12px;
        border-radius: 99px;
        font-size: 0.75rem;
        font-weight: 600;
        font-family: 'Inter', sans-serif;
        letter-spacing: 0.5px;
        margin-right: 8px;
        border: 1px solid transparent;
    }
    .b-crit { background: rgba(239, 68, 68, 0.15); color: #fca5a5; border-color: rgba(239, 68, 68, 0.3); }
    .b-high { background: rgba(245, 158, 11, 0.15); color: #fcd34d; border-color: rgba(245, 158, 11, 0.3); }
    .b-med { background: rgba(59, 130, 246, 0.15); color: #93c5fd; border-color: rgba(59, 130, 246, 0.3); }
    .b-low { background: rgba(100, 116, 139, 0.15); color: #cbd5e1; border-color: rgba(100, 116, 139, 0.3); }

    /* INPUT FIELDS - HIGH CONTRAST */
    input[type="text"] {
        background-color: #0f172a !important;
        border: 1px solid #334155 !important;
        color: #ffffff !important; /* Pure White Text */
        font-weight: 500;
        border-radius: 8px;
        padding: 12px 16px;
        font-family: 'JetBrains Mono', monospace;
        font-size: 1rem;
    }
    input[type="text"]:focus {
        border-color: #38bdf8 !important;
        box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.2);
    }
    ::placeholder { color: #64748b !important; opacity: 1; }

    /* BUTTONS */
    div.stButton > button {
        background-color: rgba(30, 41, 59, 0.5) !important;
        color: #e2e8f0 !important;
        border: 1px solid #475569 !important;
        border-radius: 8px;
        font-weight: 500;
        padding: 0.6rem 1.5rem;
    }
    div.stButton > button:hover {
        border-color: #94a3b8 !important;
        color: #ffffff !important;
        background-color: #1e293b !important;
    }
    div.stButton > button[kind="primary"] {
        background: linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%) !important;
        border: none !important;
        color: white !important;
    }

    /* TOOLKIT LINKS */
    .tool-link {
        display: block;
        padding: 12px;
        background: rgba(30, 41, 59, 0.4);
        border: 1px solid rgba(51, 65, 85, 0.5);
        border-radius: 8px;
        color: #cbd5e1 !important;
        text-decoration: none;
        font-size: 0.9rem;
        text-align: center;
        transition: all 0.2s;
    }
    .tool-link:hover {
        background: rgba(56, 189, 248, 0.1);
        border-color: #38bdf8;
        color: #38bdf8 !important;
        transform: translateY(-2px);
    }

    /* FOOTER */
    .footer {
        position: fixed; left: 0; bottom: 0; width: 100%;
        background: rgba(15, 23, 42, 0.95);
        border-top: 1px solid #1e293b;
        color: #64748b;
        text-align: center;
        padding: 10px;
        font-size: 0.75rem;
        font-family: 'JetBrains Mono', monospace;
        z-index: 999;
    }
    .footer a { color: #38bdf8 !important; text-decoration: none; font-weight: bold; }
    
    .header-credit {
        text-align: center;
        font-family: 'JetBrains Mono', monospace;
        color: #64748b;
        font-size: 0.8rem;
        margin-top: -20px;
        margin-bottom: 25px;
        letter-spacing: 2px;
        text-transform: uppercase;
    }
    
    /* RADIO GROUPS */
    div[role="radiogroup"] label {
        background: #1e293b !important;
        border: 1px solid #334155;
        padding: 8px 16px !important;
        border-radius: 6px;
        color: #94a3b8 !important;
    }
    div[role="radiogroup"] label[data-checked="true"] {
        background: #0f172a !important;
        border-color: #38bdf8 !important;
        color: #38bdf8 !important;
        font-weight: bold;
    }

    /* METRICS */
    div[data-testid="stMetricValue"] {
        color: #f8fafc !important;
        font-family: 'Inter', sans-serif;
    }
    div[data-testid="stMetricLabel"] { color: #64748b !important; }
</style>
""", unsafe_allow_html=True)

# --- INITIALIZATION ---
init_db() 
IL_TZ = pytz.timezone('Asia/Jerusalem')
REFRESH_MINUTES = 10

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

# --- AUTO-LOAD ---
if "last_run" not in st.session_state:
    st.session_state["last_run"] = datetime.datetime.now(IL_TZ)
    asyncio.run(perform_update())
else:
    now = datetime.datetime.now(IL_TZ)
    last_run = st.session_state["last_run"]
    if (now - last_run).total_seconds() > (REFRESH_MINUTES * 60):
        asyncio.run(perform_update())
        st.session_state["last_run"] = now

# --- SIDEBAR ---
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/9203/9203726.png", width=60)
    st.markdown("<h2 style='font-size: 1.5rem; margin-bottom: 0;'>CTI WAR ROOM</h2>", unsafe_allow_html=True)
    st.caption("OPERATIONAL INTELLIGENCE SUITE")
    
    st.markdown("---")
    
    st.markdown("##### SYSTEM STATUS")
    ok, msg = ConnectionManager.check_groq(GROQ_KEY)
    st.markdown(get_status_html(ok, msg), unsafe_allow_html=True)
    
    st.markdown("---")
    
    if st.button("⚡ FORCE SYNC", type="primary", use_container_width=True):
        with st.status("Executing Global Scan...", expanded=True):
            count = asyncio.run(perform_update())
            st.session_state["last_run"] = datetime.datetime.now(IL_TZ)
            st.success(f"Intel Updated: {count} new items")
            time.sleep(1)
            st.rerun()

    st.markdown("### 🛡️ DEFCON")
    st.progress(70) 
    st.caption("THREAT LEVEL: ELEVATED")

# --- HEADER & METRICS ---
st.markdown('<div class="header-credit">SYSTEM ARCHITECT: LIDOR AVRAHAMY</div>', unsafe_allow_html=True)
st.title("OPERATIONAL DASHBOARD")
st.markdown("<div style='margin-bottom: 30px; margin-top: -15px; color: #64748b;'>REAL-TIME THREAT INTELLIGENCE FEED</div>", unsafe_allow_html=True)

conn = sqlite3.connect(DB_NAME)
c = conn.cursor()
c.execute("SELECT COUNT(*) FROM intel_reports WHERE published_at > datetime('now', '-24 hours')")
count_24h = c.fetchone()[0]
c.execute("SELECT COUNT(*) FROM intel_reports WHERE severity LIKE '%Critical%' AND published_at > datetime('now', '-24 hours')")
count_crit = c.fetchone()[0]
conn.close()

m1, m2, m3, m4 = st.columns(4)
m1.metric("INTEL REPORTS (24H)", count_24h)
m2.metric("CRITICAL THREATS", count_crit, delta=count_crit, delta_color="inverse")
m3.metric("ACTIVE FEEDS", "7", "ALL SYSTEMS GO")
m4.metric("UPTIME", "99.9%", "STABLE")

st.markdown("---")

# --- TABS ---
tab_feed, tab_tools, tab_strat, tab_map = st.tabs(["🔴 LIVE FEED", "🛠️ INVESTIGATION LAB", "🧠 THREAT PROFILER", "🌍 HEATMAP"])

# --- TAB 1: LIVE FEED ---
with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    df_incd = pd.read_sql_query("SELECT * FROM intel_reports WHERE source = 'INCD' ORDER BY published_at DESC LIMIT 15", conn)
    df_others = pd.read_sql_query("SELECT * FROM intel_reports WHERE source != 'INCD' AND published_at > datetime('now', '-2 days') ORDER BY published_at DESC LIMIT 50", conn)
    conn.close()
    
    df_final = pd.concat([df_incd, df_others]).sort_values(by='published_at', ascending=False).drop_duplicates(subset=['url'])
    
    # Filters
    c1, c2 = st.columns([1, 1])
    with c1:
        st.caption("DATA SOURCE")
        filter_source = st.radio("S1", ["All Sources", "🇮🇱 INCD Only", "🌍 Global Only"], horizontal=True, label_visibility="collapsed", key="f_src")
    with c2:
        st.caption("SEVERITY FILTER")
        filter_sev = st.radio("S2", ["All Levels", "🔥 Critical/High", "⚠️ Medium", "ℹ️ Info/Low"], horizontal=True, label_visibility="collapsed", key="f_sev")

    # Apply Filters
    df_display = df_final.copy()
    if "INCD" in filter_source: df_display = df_display[df_display['source'] == 'INCD']
    elif "Global" in filter_source: df_display = df_display[df_display['source'] != 'INCD']
    
    if "Critical" in filter_sev: df_display = df_display[df_display['severity'].str.contains('Critical|High', case=False, na=False)]
    elif "Medium" in filter_sev: df_display = df_display[df_display['severity'].str.contains('Medium', case=False, na=False)]
    elif "Info" in filter_sev: df_display = df_display[df_display['severity'].str.contains('Low|Info|News', case=False, na=False)]

    st.write("") 

    if df_display.empty:
        st.info("NO THREATS DETECTED MATCHING CRITERIA.")
    
    for _, row in df_display.iterrows():
        try:
            dt = date_parser.parse(row['published_at'])
            if dt.tzinfo is None: dt = pytz.utc.localize(dt).astimezone(IL_TZ)
            else: dt = dt.astimezone(IL_TZ)
            date_str = dt.strftime('%H:%M | %d/%m')
        except: date_str = "--:--"
        
        # USE HELPER FUNCTION TO GENERATE CLEAN HTML
        st.markdown(get_feed_card_html(row, date_str), unsafe_allow_html=True)

# --- TAB 2: FORENSIC LAB ---
with tab_tools:
    st.markdown("#### 🔬 IOC FORENSICS & TOOLKIT")
    
    # TOOLKIT
    with st.expander("🧰 ANALYST QUICK ACCESS TOOLKIT", expanded=True):
        toolkit = AnalystToolkit.get_tools()
        cols = st.columns(3)
        all_tools = [t for sublist in toolkit.values() for t in sublist]
        
        for idx, tool in enumerate(all_tools):
            with cols[idx % 3]:
                st.markdown(f"""
                <a href="{tool['url']}" target="_blank" class="tool-link">
                    <b>{tool['name']}</b><br><span style="font-size:0.8em; opacity:0.7;">{tool['desc']}</span>
                </a>
                """, unsafe_allow_html=True)
    
    st.markdown("---")
    st.caption("Enter an Indicator of Compromise (IP, Domain, URL, Hash) to initiate analysis.")
    
    c_in, c_btn = st.columns([4, 1])
    with c_in:
        ioc_input = st.text_input("IOC", placeholder="e.g. 192.168.1.1, malicious.com...", label_visibility="collapsed")
    with c_btn:
        btn_scan = st.button("INITIATE SCAN", type="primary", use_container_width=True)

    if btn_scan and ioc_input:
        ioc_type = identify_ioc_type(ioc_input)
        if not ioc_type:
            st.error("❌ INVALID IOC FORMAT")
        else:
            tl = ThreatLookup(VT_KEY, URLSCAN_KEY, ABUSE_KEY)
            
            with st.spinner(f"ANALYZING {ioc_type.upper()}..."):
                vt_data = tl.query_virustotal(ioc_input, ioc_type)
                us_data = tl.query_urlscan(ioc_input) if ioc_type in ["domain", "url", "ip"] else None
                ab_data = tl.query_abuseipdb(ioc_input) if ioc_type == "ip" else None
                
                results_context = {"virustotal": vt_data, "urlscan": us_data, "abuseipdb": ab_data}
                proc = AIBatchProcessor(GROQ_KEY)
                ai_report = asyncio.run(proc.analyze_single_ioc(ioc_input, ioc_type, results_context))

            c_left, c_right = st.columns([1, 1])
            
            with c_left:
                st.markdown("##### 📊 TELEMETRY DATA")
                # VirusTotal Card
                if vt_data:
                    stats = vt_data.get('attributes', {}).get('last_analysis_stats', {})
                    mal = stats.get('malicious', 0)
                    bg_color = "rgba(239, 68, 68, 0.1)" if mal > 0 else "rgba(16, 185, 129, 0.1)"
                    border = "#ef4444" if mal > 0 else "#10b981"
                    
                    st.markdown(f"""
                    <div style="background: {bg_color}; border: 1px solid {border}; border-radius: 8px; padding: 15px; margin-bottom: 10px;">
                        <div style="font-weight: bold; color: #f8fafc;">VIRUSTOTAL DETECTION</div>
                        <div style="font-size: 1.5rem; font-family: 'JetBrains Mono'; color: #f8fafc;">{mal} / {sum(stats.values())}</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                if ab_data:
                     st.info(f"Abuse Confidence: {ab_data.get('abuseConfidenceScore', 0)}% | ISP: {ab_data.get('isp')}")
                if us_data:
                     st.info(f"URLScan Verdict: {us_data.get('verdict', {}).get('overall')}")
            
            with c_right:
                st.markdown("##### 🤖 AI ANALYST VERDICT")
                with st.container():
                     st.markdown(ai_report)

# --- TAB 3: THREAT PROFILER ---
with tab_strat:
    st.markdown("#### 🏴‍☠️ ADVERSARY DOSSIER")
    
    threats = APTSheetCollector().fetch_threats()
    names = [t['name'] for t in threats]
    
    c_sel, c_detail = st.columns([1, 3])
    
    with c_sel:
        st.caption("SELECT TARGET")
        selected = st.radio("APT", names, label_visibility="collapsed")
        actor = next(t for t in threats if t['name'] == selected)
        
        st.markdown("---")
        if st.button("GENERATE HUNTING RULES", use_container_width=True):
            with st.spinner("Compiling Detection Logic..."):
                proc = AIBatchProcessor(GROQ_KEY)
                rules = asyncio.run(proc.generate_hunting_queries(actor))
                st.session_state['hunt_rules'] = rules

    with c_detail:
        # USE HELPER FUNCTION TO GENERATE CLEAN HTML
        st.markdown(get_dossier_html(actor), unsafe_allow_html=True)

        if 'hunt_rules' in st.session_state:
            st.markdown("---")
            st.markdown("##### 🛡️ DETECTION LOGIC (XQL / YARA)")
            st.markdown(st.session_state['hunt_rules'])

# --- TAB 4: MAP ---
with tab_map:
    st.markdown("#### 🌍 GLOBAL CYBER ATTACK MAP")
    components.iframe("https://threatmap.checkpoint.com/", height=700)

# --- FOOTER ---
st.markdown("""
<div class="footer">
    SYSTEM ARCHITECT: <b>LIDOR AVRAHAMY</b> &nbsp;|&nbsp; 
    <a href="https://www.linkedin.com/in/lidoravrahamy/" target="_blank">LINKEDIN PROFILE</a>
</div>
""", unsafe_allow_html=True)
