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

# --- CONFIGURATION ---
st.set_page_config(page_title="CTI WAR ROOM", layout="wide", page_icon="🛡️")

# --- UI STYLING (DARK MODE) ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600&family=JetBrains+Mono:wght@400;700&family=Heebo:wght@300;400;700&display=swap');
    
    .stApp {
        background-color: #0b0f19;
        background-image: radial-gradient(circle at 50% 0%, #1c2541 0%, #0b0f19 50%);
        font-family: 'Heebo', sans-serif;
    }
    
    h1, h2, h3 { font-family: 'Inter', sans-serif; font-weight: 600; color: #ffffff !important; }
    p, div, span { color: #cbd5e1; line-height: 1.6; }

    /* CARDS */
    .report-card {
        background: rgba(30, 41, 59, 0.4);
        backdrop-filter: blur(12px);
        border: 1px solid rgba(148, 163, 184, 0.1);
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 20px;
    }
    .card-incd { border-right: 4px solid #3b82f6; }
    .card-global { border-left: 4px solid #10b981; }
    .card-title { font-size: 1.25rem; font-weight: 700; color: #f1f5f9; margin-bottom: 12px; }
    .card-meta { font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: #94a3b8; }

    /* FOOTER */
    .footer { position: fixed; left: 0; bottom: 0; width: 100%; background: rgba(15, 23, 42, 0.95); text-align: center; padding: 10px; font-size: 0.75rem; color: #64748b; z-index: 999; }
    div[data-testid="stMetricValue"] { color: #f8fafc !important; }
    
    .update-info { font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: #64748b; margin-top: -10px; margin-bottom: 20px; display: flex; gap: 15px; }
    .update-tag { background: #1e293b; padding: 2px 8px; border-radius: 4px; border: 1px solid #334155; }
    
    input[type="text"] { background-color: #0f172a !important; color: white !important; border: 1px solid #334155 !important; }
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

# --- AUTO-REFRESH ---
st_autorefresh(interval=REFRESH_MINUTES * 60 * 1000, key="data_refresh")

# --- UPDATE LOGIC ---
async def perform_update():
    col, proc = CTICollector(), AIBatchProcessor(GROQ_KEY)
    raw = await col.get_all_data() # Includes automated DeepWeb scans
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
    
    ok, msg = ConnectionManager.check_groq(GROQ_KEY)
    color = "#4ade80" if ok else "#f87171"
    st.markdown(f"""
    <div style="background: #1e293b; padding: 10px; border-radius: 8px; margin-bottom: 10px; border: 1px solid #334155; display: flex; justify-content: space-between;">
        <span style="color: #cbd5e1;">AI Engine</span>
        <span style="color: {color}; font-weight: bold;">● {'ONLINE' if ok else 'OFFLINE'}</span>
    </div>
    """, unsafe_allow_html=True)
    
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

last_run = st.session_state["last_run"]
next_run = last_run + datetime.timedelta(minutes=REFRESH_MINUTES)
st.markdown(f"""
<div class="update-info">
    <span class="update-tag">🕒 LAST: {last_run.strftime('%H:%M')}</span>
    <span class="update-tag" style="color: #38bdf8; border-color: #0c4a6e;">🔄 NEXT: {next_run.strftime('%H:%M')}</span>
</div>
""", unsafe_allow_html=True)

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
    # FILTER: Exclude DeepWeb from Live Feed
    df_incd = pd.read_sql_query("SELECT * FROM intel_reports WHERE source = 'INCD' AND published_at > datetime('now', '-2 days') ORDER BY published_at DESC LIMIT 15", conn)
    df_others = pd.read_sql_query("SELECT * FROM intel_reports WHERE source NOT IN ('INCD', 'DeepWeb') AND published_at > datetime('now', '-2 days') ORDER BY published_at DESC LIMIT 50", conn)
    conn.close()
    
    df_final = pd.concat([df_incd, df_others]).sort_values(by='published_at', ascending=False).drop_duplicates(subset=['url'])
    
    c1, c2 = st.columns([1, 1])
    with c1:
        st.caption("DATA SOURCE")
        filter_source = st.radio("S1", ["All Sources", "🇮🇱 INCD Only", "🌍 Global Only"], horizontal=True, label_visibility="collapsed", key="f_src")
    with c2:
        st.caption("SEVERITY FILTER")
        filter_sev = st.radio("S2", ["All Levels", "🔥 Critical/High", "⚠️ Medium", "ℹ️ Info/Low"], horizontal=True, label_visibility="collapsed", key="f_sev")

    df_display = df_final.copy()
    if "INCD" in filter_source: df_display = df_display[df_display['source'] == 'INCD']
    elif "Global" in filter_source: df_display = df_display[df_display['source'] != 'INCD']
    
    if "Critical" in filter_sev: df_display = df_display[df_display['severity'].str.contains('Critical|High', case=False, na=False)]
    elif "Medium" in filter_sev: df_display = df_display[df_display['severity'].str.contains('Medium', case=False, na=False)]
    elif "Info" in filter_sev: df_display = df_display[df_display['severity'].str.contains('Low|Info|News', case=False, na=False)]

    st.write("") 
    if df_display.empty: st.info("NO THREATS DETECTED MATCHING CRITERIA.")
    
    for _, row in df_display.iterrows():
        try:
            dt = date_parser.parse(row['published_at'])
            if dt.tzinfo is None: dt = pytz.utc.localize(dt).astimezone(IL_TZ)
            else: dt = dt.astimezone(IL_TZ)
            date_str = dt.strftime('%H:%M | %d/%m')
        except: date_str = "--:--"
        
        # HTML CARD GENERATION INLINE FOR CONSISTENCY
        is_incd = row['source'] == "INCD"
        card_class = "card-incd" if is_incd else "card-global"
        sev = row['severity'].lower()
        badge_bg = "rgba(220, 38, 38, 0.2)" if "critical" in sev or "high" in sev else "rgba(100, 116, 139, 0.2)"
        badge_color = "#fca5a5" if "critical" in sev or "high" in sev else "#cbd5e1"
        
        st.markdown(f"""
        <div class="report-card {card_class}" style="direction: {'rtl' if is_incd else 'ltr'};">
            <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                <div class="card-meta">{date_str} • {row['source']}</div>
                <div style="background: {badge_bg}; color: {badge_color}; padding: 2px 10px; border-radius: 99px; font-size: 0.75rem;">{row['severity'].upper()}</div>
            </div>
            <div class="card-title">{row['title']}</div>
            <div style="color: #cbd5e1; opacity: 0.9; margin-bottom: 10px;">{clean_html(row['summary'])}</div>
            <a href="{row['url']}" target="_blank" style="color: #38bdf8; text-decoration: none; font-weight: bold;">OPEN REPORT 🔗</a>
        </div>
        """, unsafe_allow_html=True)

# --- TAB 2: FORENSIC LAB ---
with tab_tools:
    st.markdown("#### 🔬 IOC FORENSICS & TOOLKIT")
    with st.expander("🧰 ANALYST QUICK ACCESS TOOLKIT", expanded=True):
        toolkit = AnalystToolkit.get_tools()
        cols = st.columns(3)
        all_tools = [t for sublist in toolkit.values() for t in sublist]
        for idx, tool in enumerate(all_tools):
            with cols[idx % 3]:
                st.markdown(f"""<a href="{tool['url']}" target="_blank" class="tool-link"><b>{tool['name']}</b><br><span style="font-size:0.8em; opacity:0.7;">{tool['desc']}</span></a>""", unsafe_allow_html=True)
    
    st.markdown("---")
    st.caption("Enter an Indicator of Compromise (IP, Domain, URL, Hash) to initiate analysis.")
    c_in, c_btn = st.columns([4, 1])
    with c_in: ioc_input = st.text_input("IOC", placeholder="e.g. 192.168.1.1, malicious.com...", label_visibility="collapsed")
    with c_btn: btn_scan = st.button("INITIATE SCAN", type="primary", use_container_width=True)

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
                
                # Safety Block for AI Rate Limits
                try:
                    ai_report = asyncio.run(proc.analyze_single_ioc(ioc_input, ioc_type, results_context))
                    if "Error" in str(ai_report) and "429" in str(ai_report):
                        ai_report = "⚠️ **AI Rate Limit Reached:** Please wait a moment before the next scan."
                except Exception as e:
                     ai_report = f"⚠️ AI Analysis Unavailable: {str(e)}"

            c_left, c_right = st.columns([1, 1])
            with c_left:
                st.markdown("##### 📊 TELEMETRY DATA")
                # VirusTotal
                if vt_data:
                    attrs = vt_data.get('attributes', {})
                    stats = attrs.get('last_analysis_stats', {})
                    mal = stats.get('malicious', 0)
                    bg_color = "rgba(239, 68, 68, 0.1)" if mal > 0 else "rgba(16, 185, 129, 0.1)"
                    border = "#ef4444" if mal > 0 else "#10b981"
                    
                    st.markdown(f"""
                    <div style="background: {bg_color}; border: 1px solid {border}; border-radius: 8px; padding: 15px; margin-bottom: 10px;">
                        <div style="font-weight: bold; color: #f8fafc;">VIRUSTOTAL DETECTION</div>
                        <div style="font-size: 1.5rem; font-family: 'JetBrains Mono'; color: #f8fafc;">{mal} / {sum(stats.values())}</div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    with st.expander("🔍 Deep Dive (Metadata)", expanded=False):
                         if attrs.get('country'): st.write(f"**Country:** {attrs.get('country')} 🌍")
                         if attrs.get('as_owner'): st.write(f"**AS Owner:** {attrs.get('as_owner')} ({attrs.get('asn', '')})")
                         st.write(f"**Reputation:** {attrs.get('reputation', 0)}")
                         st.write(f"**Tags:** {', '.join(attrs.get('tags', []))}")
                    with st.expander("🕸️ Network Relations", expanded=False):
                        rels = vt_data.get('relationships', {})
                        if rels.get('resolutions'):
                             st.write("**Passive DNS:**")
                             for r in rels['resolutions'].get('data', [])[:5]: st.code(r.get('attributes', {}).get('host_name', 'Unknown'))
                        if rels.get('contacted_urls'):
                             st.write("**Contacted URLs:**")
                             for u in rels['contacted_urls'].get('data', [])[:5]: st.code(u.get('context_attributes', {}).get('url', u.get('id', '')))

                # AbuseIPDB (FIXED: Display logic updated)
                if ab_data: 
                     st.markdown(f"""
                     <div style="background: rgba(59, 130, 246, 0.1); border: 1px solid #3b82f6; border-radius: 8px; padding: 10px; margin-top: 10px;">
                        <div style="font-weight: bold; color: #93c5fd; margin-bottom: 5px;">ABUSEIPDB PROFILE</div>
                        <div><b>Score:</b> {ab_data.get('abuseConfidenceScore', 0)}%</div>
                        <div><b>ISP:</b> {ab_data.get('isp', 'N/A')}</div>
                        <div><b>Usage:</b> {ab_data.get('usageType', 'Unknown')}</div>
                        <div><b>Domain:</b> {ab_data.get('domain', 'N/A')}</div>
                     </div>
                     """, unsafe_allow_html=True)

                # URLScan
                if us_data:
                    task = us_data.get('task', {})
                    page = us_data.get('page', {})
                    st.info(f"""
                    **URLScan Verdict: {us_data.get('verdict', {}).get('overall')}**
                    - Target: {task.get('url', 'N/A')}
                    - Location: {page.get('country', 'Unknown')}
                    - Server: {page.get('server', 'N/A')}
                    """)
                    if task.get('screenshotURL'): st.image(task['screenshotURL'])
            
            with c_right:
                st.markdown("##### 🤖 AI ANALYST VERDICT")
                with st.container(): st.markdown(ai_report)

# --- TAB 3: THREAT PROFILER (RESTORED CAMPAIGN RADAR) ---
with tab_strat:
    st.markdown("#### 🏴‍☠️ ADVERSARY DOSSIER")
    threats = APTSheetCollector().fetch_threats()
    names = [t['name'] for t in threats]
    
    # Selection Row
    c_sel, c_detail = st.columns([1, 2])
    
    with c_sel:
        st.caption("SELECT TARGET")
        selected = st.radio("APT", names, label_visibility="collapsed")
        actor = next(t for t in threats if t['name'] == selected)
        st.markdown("---")
        if st.button("GENERATE HUNTING RULES", use_container_width=True):
            with st.spinner("Compiling Detection Logic..."):
                proc = AIBatchProcessor(GROQ_KEY)
                try:
                    rules = asyncio.run(proc.generate_hunting_queries(actor))
                    if "Error" in str(rules) and "429" in str(rules):
                        st.warning(f"⚠️ **AI Limit Reached:** {rules}")
                    elif "Error" in str(rules):
                        st.warning(f"⚠️ AI Busy: {rules}")
                    else:
                        st.session_state['hunt_rules'] = rules
                except Exception as e:
                    st.error(f"Analysis Failed: {str(e)}")

    with c_detail:
        # Generate Dossier HTML
        st.markdown(f"""
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
        """, unsafe_allow_html=True)
        
        if 'hunt_rules' in st.session_state:
            st.markdown("---")
            st.markdown("##### 🛡️ DETECTION LOGIC (XQL / YARA)")
            st.markdown(st.session_state['hunt_rules'])

    st.markdown("---")
    
    # --- CAMPAIGN RADAR (RESTORED & IMPROVED) ---
    st.markdown("##### 📡 LATEST INTEL FEED (LIVE DB SEARCH)")
    
    # Perform Search in DB for Actor (All history, top 5, INCLUDING DeepWeb)
    conn = sqlite3.connect(DB_NAME)
    keywords = actor.get('keywords', []) + [actor['name']]
    query_parts = [f"title LIKE '%{k}%' OR summary LIKE '%{k}%'" for k in keywords]
    full_query = f"SELECT * FROM intel_reports WHERE { ' OR '.join(query_parts) } ORDER BY published_at DESC LIMIT 5"
    df_hits = pd.read_sql_query(full_query, conn)
    conn.close()

    if not df_hits.empty:
        st.success(f"Tracked {len(df_hits)} recent intelligence reports linked to {actor['name']}")
        for _, row in df_hits.iterrows():
            try: dt = date_parser.parse(row['published_at']).strftime('%d/%m/%Y')
            except: dt = "?"
            
            # Using the existing card style for consistency
            is_incd = row['source'] == "INCD"
            card_class = "card-incd" if is_incd else "card-global"
            st.markdown(f"""
            <div class="report-card {card_class}" style="direction: {'rtl' if is_incd else 'ltr'};">
                <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                    <div class="card-meta">{dt} • {row['source']}</div>
                    <div style="background: rgba(100, 116, 139, 0.2); color: #cbd5e1; padding: 2px 10px; border-radius: 99px; font-size: 0.75rem;">{row['severity'].upper()}</div>
                </div>
                <div class="card-title">{row['title']}</div>
                <div style="color: #cbd5e1; opacity: 0.9; margin-bottom: 10px;">{clean_html(row['summary'])}</div>
                <a href="{row['url']}" target="_blank" style="color: #38bdf8; text-decoration: none; font-weight: bold;">OPEN REPORT 🔗</a>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info(f"No specific mentions of {actor['name']} found in the collected feeds.")
        
    st.caption(f"This feed automatically scans open sources for '{actor['name']}' every 15 minutes.")

# --- TAB 4: MAP ---
with tab_map:
    st.markdown("#### 🌍 GLOBAL CYBER ATTACK MAP")
    components.iframe("https://threatmap.checkpoint.com/", height=700)

# --- FOOTER ---
st.markdown("""<div class="footer">SYSTEM ARCHITECT: <b>LIDOR AVRAHAMY</b> &nbsp;|&nbsp; <a href="https://www.linkedin.com/in/lidoravrahamy/" target="_blank">LINKEDIN PROFILE</a></div>""", unsafe_allow_html=True)
