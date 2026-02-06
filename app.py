import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import datetime
import pytz
import time
import re
import streamlit.components.v1 as components
from utils import *
from dateutil import parser as date_parser
from streamlit_autorefresh import st_autorefresh

# --- CONFIGURATION & RTL SETUP ---
st.set_page_config(page_title="CTI WAR ROOM", layout="wide", page_icon="🛡️")

# --- HTML GENERATORS (RTL & DARK MODE) ---
def clean_html(raw_html):
    cleanr = re.compile('<.*?>')
    cleantext = re.sub(cleanr, '', str(raw_html))
    return cleantext.replace('"', '&quot;').strip()

def get_status_html(ok, msg):
    color = "#4ade80" if ok else "#f87171"
    status = "ONLINE" if ok else "OFFLINE"
    return f"""
    <div style="direction: ltr; display: flex; align-items: center; justify-content: space-between; background: #1e293b; padding: 10px; border-radius: 8px; margin-bottom: 10px; border: 1px solid #334155;">
        <span style="font-size: 0.9rem; color: #cbd5e1; font-family: 'Inter', sans-serif;">AI Engine</span>
        <span style="font-size: 0.8rem; color: {color}; font-weight: bold; font-family: 'JetBrains Mono', monospace; letter-spacing: 1px;">● {status}</span>
    </div>
    """

def get_feed_card_html(row, date_str):
    # Determine direction and styling
    # INCD is strictly RTL/Hebrew.
    # Other sources are translated to Hebrew, so also RTL.
    dir = 'rtl'
    align = 'right'
    
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
        
    source_display = f"🇮🇱 {row['source']}" if row['source'] == 'INCD' else f"📡 {row['source']}"
    
    clean_summary = clean_html(row['summary'])
    
    return f"""
    <div class="report-card" style="direction: {dir}; text-align: {align}; border-right: 4px solid {border_color};">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-direction: row-reverse;">
             <div style="background: {badge_bg}; color: {badge_color}; border: 1px solid {border_color}; padding: 2px 10px; border-radius: 99px; font-size: 0.75rem; font-weight: bold; letter-spacing: 0.5px;">
                {row['severity'].upper()}
            </div>
            <div class="card-meta">
                {date_str} • <b style="color: #e2e8f0;">{source_display}</b>
            </div>
        </div>
        <div class="card-title">{row['title']}</div>
        <div style="font-size: 0.95rem; color: #cbd5e1; margin-bottom: 15px; line-height: 1.6; opacity: 0.9;">
            {clean_summary}
        </div>
        <div style="text-align: left;">
            <a href="{row['url']}" target="_blank" style="display: inline-flex; align-items: center; gap: 5px; color: #38bdf8; text-decoration: none; font-size: 0.85rem; font-weight: 600; padding: 5px 10px; background: rgba(56, 189, 248, 0.1); border-radius: 6px; transition: all 0.2s;">
                פתח מקור 🔗
            </a>
        </div>
    </div>
    """

def get_dossier_html(actor):
    return f"""
    <div class="report-card" style="direction: ltr; border-left: 4px solid #f59e0b; background: linear-gradient(180deg, rgba(30, 41, 59, 0.6) 0%, rgba(15, 23, 42, 0.8) 100%);">
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

# --- CYBER BOOT SEQUENCE & AUTO DEEP SCAN ---
if 'booted' not in st.session_state:
    st.markdown("""<style>.stApp { background-color: #000000; }</style>""", unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.write(""); st.write(""); st.write("")
        st.image("https://cdn-icons-png.flaticon.com/512/9203/9203726.png", width=100)
        st.markdown("<h3 style='text-align: center; color: #ffffff;'>SYSTEM INITIALIZATION</h3>", unsafe_allow_html=True)
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        # Initialization Steps
        steps = ["Connecting to Threat Feeds...", "Syncing INCD Database...", "Initializing Gemini Translation Module..."]
        for i, step in enumerate(steps):
            status_text.write(step)
            time.sleep(0.3)
            progress_bar.progress((i + 1) * 20)
        
        # --- AUTOMATIC DEEP SCAN ALL GROUPS ---
        status_text.write("🔎 Performing Full Spectrum Deep Scan (All Actors)...")
        # Initialize Backend
        GROQ_KEY = st.secrets.get("groq_key", "")
        scanner = DeepWebScanner()
        proc = AIBatchProcessor(GROQ_KEY)
        threats = APTSheetCollector().fetch_threats()
        
        all_deep_hits = []
        for threat in threats:
            # Perform quick scan per actor
            hits = scanner.scan_actor(threat['name'], limit=2) # Limit to 2 per actor to save boot time
            all_deep_hits.extend(hits)
        
        if all_deep_hits:
             status_text.write(f"🧠 AI Analyzing {len(all_deep_hits)} Deep Web artifacts...")
             # Run AI Analysis (Async wrapper)
             analyzed_hits = asyncio.run(proc.analyze_batch(all_deep_hits))
             save_reports(all_deep_hits, analyzed_hits)
        
        progress_bar.progress(100)
        status_text.write("Access Granted.")
        time.sleep(0.5)
        st.session_state['booted'] = True
        st.rerun()

# --- UI STYLING (RTL & HEBREW) ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Rubik:wght@300;400;600&family=Heebo:wght@300;400;700&display=swap');
    
    /* RTL GLOBAL SETTINGS */
    .stApp {
        direction: rtl;
        text-align: right;
        background-color: #0b0f19;
        font-family: 'Heebo', sans-serif;
    }
    
    h1, h2, h3, h4, h5, h6, p, div, span, label, .stMarkdown {
        text-align: right; 
        font-family: 'Heebo', sans-serif;
    }

    /* GLASSMORPHISM CARDS */
    .report-card {
        background: rgba(30, 41, 59, 0.4);
        backdrop-filter: blur(12px);
        border: 1px solid rgba(148, 163, 184, 0.1);
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 20px;
    }
    .card-title {
        font-size: 1.25rem;
        font-weight: 700;
        color: #f1f5f9;
        margin-bottom: 12px;
        text-align: right;
    }
    .card-meta {
        font-family: 'Rubik', sans-serif;
        font-size: 0.85rem;
        color: #94a3b8;
    }

    /* BADGES */
    .badge {
        display: inline-flex;
        align-items: center;
        padding: 4px 12px;
        border-radius: 99px;
        font-size: 0.75rem;
        font-weight: 600;
        margin-left: 8px; /* RTL Margin */
    }
    .b-crit { background: rgba(239, 68, 68, 0.15); color: #fca5a5; }
    .b-high { background: rgba(245, 158, 11, 0.15); color: #fcd34d; }
    .b-med { background: rgba(59, 130, 246, 0.15); color: #93c5fd; }

    /* INPUTS & BUTTONS */
    input[type="text"] {
        text-align: right;
        direction: rtl;
        background-color: #0f172a !important;
        color: white !important;
    }
    div.stButton > button {
        width: 100%;
        font-family: 'Rubik', sans-serif;
    }
    
    /* TABS ALIGNMENT */
    .stTabs [data-baseweb="tab-list"] {
        justify-content: flex-end;
        gap: 20px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        direction: rtl;
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
        z-index: 999;
        direction: ltr; /* Footer kept LTR for English credits */
    }
</style>
""", unsafe_allow_html=True)

# --- INITIALIZATION ---
init_db() 
IL_TZ = pytz.timezone('Asia/Jerusalem')
REFRESH_MINUTES = 15

GROQ_KEY = st.secrets.get("groq_key", "")
VT_KEY = st.secrets.get("vt_key", "")
URLSCAN_KEY = st.secrets.get("urlscan_key", "")
ABUSE_KEY = st.secrets.get("abuseipdb_key", "")

# --- AUTO-REFRESH LOGIC ---
st_autorefresh(interval=REFRESH_MINUTES * 60 * 1000, key="data_refresh")

async def perform_update():
    col, proc = CTICollector(), AIBatchProcessor(GROQ_KEY)
    raw = await col.get_all_data()
    if raw:
        analyzed = await proc.analyze_batch(raw)
        return save_reports(raw, analyzed)
    return 0

if "last_run" not in st.session_state:
    st.session_state["last_run"] = datetime.datetime.now(IL_TZ)
    asyncio.run(perform_update())

# --- SIDEBAR (RTL) ---
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/9203/9203726.png", width=60)
    st.markdown("<h2 style='text-align: right;'>CTI WAR ROOM</h2>", unsafe_allow_html=True)
    st.caption("מערכת מודיעין מבצעית")
    st.markdown("---")
    st.markdown("##### סטטוס מערכת")
    ok, msg = ConnectionManager.check_groq(GROQ_KEY)
    st.markdown(get_status_html(ok, msg), unsafe_allow_html=True)
    st.markdown("---")
    if st.button("⚡ סנכרון ידני (Force Sync)", type="primary"):
        with st.status("מבצע סריקה גלובלית...", expanded=True):
            count = asyncio.run(perform_update())
            st.session_state["last_run"] = datetime.datetime.now(IL_TZ)
            st.success(f"עודכן: {count} ידיעות חדשות")
            time.sleep(1)
            st.rerun()

# --- HEADER & METRICS ---
st.title("לוח בקרה מבצעי")

conn = sqlite3.connect(DB_NAME)
c = conn.cursor()
# Only count regular feeds for main stats (exclude DeepWeb noise)
c.execute("SELECT COUNT(*) FROM intel_reports WHERE published_at > datetime('now', '-24 hours') AND source != 'DeepWeb'")
count_24h = c.fetchone()[0]
c.execute("SELECT COUNT(*) FROM intel_reports WHERE severity LIKE '%Critical%' AND published_at > datetime('now', '-24 hours') AND source != 'DeepWeb'")
count_crit = c.fetchone()[0]
conn.close()

# RTL Metrics
m4, m3, m2, m1 = st.columns(4) # Reversed order for visual RTL
m1.metric("ידיעות (24ש)", count_24h)
m2.metric("התרעות קריטיות", count_crit, delta=count_crit, delta_color="inverse")
m3.metric("מקורות פעילים", "7", "תקין")
m4.metric("זמינות מערכת", "100%", "יציב")

st.markdown("---")

# --- TABS ---
tab_feed, tab_strat, tab_tools, tab_map = st.tabs(["🔴 עדכונים שוטפים (Live)", "🗂️ תיקי תקיפה (Dossier)", "🛠️ מעבדת חקירות", "🌍 מפת תקיפות"])

# --- TAB 1: LIVE FEED (EXCLUDE DEEPWEB) ---
with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    # Query excludes 'DeepWeb' source to keep this feed clean
    df_incd = pd.read_sql_query("SELECT * FROM intel_reports WHERE source = 'INCD' ORDER BY published_at DESC LIMIT 15", conn)
    df_others = pd.read_sql_query("SELECT * FROM intel_reports WHERE source != 'INCD' AND source != 'DeepWeb' AND published_at > datetime('now', '-2 days') ORDER BY published_at DESC LIMIT 50", conn)
    conn.close()
    
    df_final = pd.concat([df_incd, df_others]).sort_values(by='published_at', ascending=False).drop_duplicates(subset=['url'])
    
    c1, c2 = st.columns([1, 1])
    with c1:
        filter_source = st.radio("מקור מידע", ["הכל", "🇮🇱 מערך הסייבר", "🌍 מקורות עולמיים"], horizontal=True, key="f_src")
    with c2:
        filter_sev = st.radio("רמת חומרה", ["הכל", "🔥 קריטי/גבוה", "⚠️ בינוני", "ℹ️ מידע/נמוך"], horizontal=True, key="f_sev")

    df_display = df_final.copy()
    if "מערך הסייבר" in filter_source: df_display = df_display[df_display['source'] == 'INCD']
    elif "עולמיים" in filter_source: df_display = df_display[df_display['source'] != 'INCD']
    
    if "קריטי" in filter_sev: df_display = df_display[df_display['severity'].str.contains('Critical|High', case=False, na=False)]
    elif "בינוני" in filter_sev: df_display = df_display[df_display['severity'].str.contains('Medium', case=False, na=False)]
    elif "נמוך" in filter_sev: df_display = df_display[df_display['severity'].str.contains('Low|Info|News', case=False, na=False)]

    st.write("") 
    if df_display.empty: st.info("לא נמצאו התרעות התואמות את הסינון.")
    
    for _, row in df_display.iterrows():
        try:
            # Display Actual Published Date
            dt = date_parser.parse(row['published_at'])
            if dt.tzinfo is None: dt = pytz.utc.localize(dt).astimezone(IL_TZ)
            else: dt = dt.astimezone(IL_TZ)
            date_str = dt.strftime('%H:%M | %d/%m')
        except: date_str = "--:--"
        st.markdown(get_feed_card_html(row, date_str), unsafe_allow_html=True)

# --- TAB 2: ADVERSARY DOSSIER (DEEP WEB RESULTS) ---
with tab_strat:
    st.markdown("#### 🏴‍☠️ פרופיל קבוצות תקיפה ו-Deep Scan")
    threats = APTSheetCollector().fetch_threats()
    names = [t['name'] for t in threats]
    
    c_sel, c_detail = st.columns([1, 2])
    
    with c_sel:
        st.caption("בחר קבוצת תקיפה")
        selected = st.radio("APT", names, label_visibility="collapsed")
        actor = next(t for t in threats if t['name'] == selected)
        
    with c_detail:
        st.markdown(get_dossier_html(actor), unsafe_allow_html=True)

    st.markdown("---")
    
    # --- DEEP WEB RESULTS DISPLAY ---
    st.markdown(f"##### 🕵️ תוצאות סריקת עומק (Deep Scan Import) - {actor['name']}")
    st.caption("תוצאות אלו נאספו באופן אוטומטי מה-Deep Web ולא מופיעות ב-Feed הרגיל.")
    
    conn = sqlite3.connect(DB_NAME)
    # Fetch ONLY DeepWeb results related to this actor
    # We search by actor_tag OR keyword match
    keywords = actor.get('keywords', []) + [actor['name']]
    query_parts = [f"title LIKE '%{k}%' OR summary LIKE '%{k}%'" for k in keywords]
    
    # Combine Logic: Source MUST be DeepWeb AND (ActorTag matches OR Keywords match)
    deep_query = f"""
    SELECT * FROM intel_reports 
    WHERE source = 'DeepWeb' 
    AND (actor_tag = '{actor['name']}' OR ({ ' OR '.join(query_parts) }))
    ORDER BY published_at DESC LIMIT 10
    """
    df_deep = pd.read_sql_query(deep_query, conn)
    conn.close()

    if not df_deep.empty:
        for _, row in df_deep.iterrows():
             try: dt = date_parser.parse(row['published_at']).strftime('%d/%m/%Y')
             except: dt = "?"
             st.markdown(get_feed_card_html(row, dt), unsafe_allow_html=True)
    else:
        st.info("לא נמצאו ממצאי Deep Web עדכניים עבור קבוצה זו בסריקה האחרונה.")

# --- TAB 3: INVESTIGATION LAB ---
with tab_tools:
    st.markdown("#### 🔬 מעבדת חקירות (IOC Analysis)")
    
    c_in, c_btn = st.columns([4, 1])
    with c_in: ioc_input = st.text_input("הזן אינדיקטור (IP, Hash, Domain)", placeholder="לדוגמה: 192.168.1.1...")
    with c_btn: btn_scan = st.button("בצע חקירה", type="primary")

    if btn_scan and ioc_input:
        ioc_type = identify_ioc_type(ioc_input)
        if not ioc_type:
            st.error("❌ פורמט לא תקין")
        else:
            tl = ThreatLookup(VT_KEY, URLSCAN_KEY, ABUSE_KEY)
            with st.spinner(f"מבצע אנליזה על {ioc_type.upper()}..."):
                vt_data = tl.query_virustotal(ioc_input, ioc_type)
                us_data = tl.query_urlscan(ioc_input) if ioc_type in ["domain", "url", "ip"] else None
                ab_data = tl.query_abuseipdb(ioc_input) if ioc_type == "ip" else None
                
                results_context = {"virustotal": vt_data, "urlscan": us_data, "abuseipdb": ab_data}
                proc = AIBatchProcessor(GROQ_KEY)
                
                try:
                    # Keep English for technical analysis as per industry standard
                    ai_report = asyncio.run(proc.analyze_single_ioc(ioc_input, ioc_type, results_context))
                except Exception as e:
                     ai_report = f"⚠️ שגיאה באנליזת AI: {str(e)}"

            c_left, c_right = st.columns([1, 1])
            with c_right: # RTL Switch
                st.markdown("##### 📊 נתונים טכניים")
                if vt_data:
                    stats = vt_data.get('attributes', {}).get('last_analysis_stats', {})
                    mal = stats.get('malicious', 0)
                    st.metric("VirusTotal Zihuy", f"{mal} / {sum(stats.values())}")
            
            with c_left:
                st.markdown("##### 🤖 חוות דעת אנליסט (AI)")
                with st.container(): st.markdown(ai_report, unsafe_allow_html=True) # Usually keeps English markdown

# --- TAB 4: MAP ---
with tab_map:
    st.markdown("#### 🌍 מפת תקיפות זמן אמת")
    components.iframe("https://threatmap.checkpoint.com/", height=700)

# --- FOOTER ---
st.markdown("""<div class="footer">SYSTEM ARCHITECT: <b>LIDOR AVRAHAMY</b></div>""", unsafe_allow_html=True)
