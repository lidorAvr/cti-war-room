import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import datetime
import pytz
import time
import re
import os
import streamlit.components.v1 as components
from utils import *
from dateutil import parser as date_parser

# --- CONFIGURATION ---
st.set_page_config(page_title="CTI WAR ROOM", layout="wide", page_icon="🛡️")

# --- CSS STYLING (English / native LTR) ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Rubik:wght@300;400;600&family=Inter:wght@300;400;600;700&family=Heebo:wght@300;400;700&display=swap');
    .stApp { background-color: #0b0f19; font-family: 'Inter', 'Heebo', sans-serif; }
    .stButton button { width: 100%; font-family: 'Rubik', sans-serif; border-radius: 8px; }
    .tool-card {
        background: rgba(30, 41, 59, 0.7); border: 1px solid rgba(56, 189, 248, 0.3);
        border-radius: 12px; padding: 20px; text-align: center; margin-bottom: 15px;
        height: 100%; color: white; transition: all 0.3s;
    }
    .tool-card:hover { background: rgba(56, 189, 248, 0.2); border-color: #38bdf8; transform: translateY(-4px); }
    .tool-icon { font-size: 32px; margin-bottom: 10px; display: block; }
    .tool-name { font-weight: 700; color: #f1f5f9; display: block; margin-bottom: 5px; font-size: 1.1rem; }
    .tool-desc { font-size: 0.85rem; color: #cbd5e1; display: block; line-height: 1.4; }
    a { text-decoration: none; }
    .report-card {
        background: rgba(30, 41, 59, 0.4); backdrop-filter: blur(12px);
        border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 12px; padding: 24px; margin-bottom: 20px;
    }
    .ioc-card { padding: 15px; border-radius: 10px; text-align: center; color: white; margin-bottom: 10px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
    .ioc-safe { background: linear-gradient(135deg, #10b981, #059669); }
    .ioc-danger { background: linear-gradient(135deg, #ef4444, #b91c1c); }
    .ioc-neutral { background: linear-gradient(135deg, #64748b, #475569); }
    .ioc-title { font-size: 0.9rem; font-weight: bold; opacity: 0.9; }
    .ioc-value { font-size: 1.8rem; font-weight: bold; margin: 5px 0; }
    .ioc-sub { font-size: 0.75rem; opacity: 0.85; }
    .redirect-alert { background: rgba(245, 158, 11, 0.2); border: 1px solid #f59e0b; color: #fcd34d; padding: 15px; border-radius: 8px; margin-bottom: 15px; }
    .footer { text-align: center; color: #475569; font-size: 0.8rem; margin-top: 30px; }
</style>
""", unsafe_allow_html=True)

def clean_html(raw_html):
    cleanr = re.compile('<.*?>')
    return re.sub(cleanr, '', str(raw_html)).replace('"', '&quot;').strip()

def get_feed_card_html(row, date_str):
    sev = row['severity'].lower()
    badge_bg, badge_color, border_color = "rgba(100, 116, 139, 0.2)", "#cbd5e1", "rgba(100, 116, 139, 0.3)"
    if "critical" in sev or "high" in sev: badge_bg, badge_color, border_color = "rgba(220, 38, 38, 0.2)", "#fca5a5", "#ef4444"
    elif "medium" in sev: badge_bg, badge_color, border_color = "rgba(59, 130, 246, 0.2)", "#93c5fd", "#3b82f6"
    summary = clean_html(row['summary']).replace('\n', '<br>')
    is_raw = str(row.get('category', '')).lower() == 'raw'
    raw_badge = ('<div style="background: rgba(148,163,184,0.12); color:#94a3b8; border:1px solid #475569; padding:2px 10px; border-radius:99px; font-size:0.7rem;">RAW · no AI</div>' if is_raw else '')
    # dir="auto" lets each item render in its own language direction:
    # Hebrew AI summaries -> RTL, English raw items -> LTR, automatically.
    return f"""
    <div class="report-card" style="border-left: 4px solid {border_color};">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <div style="font-family: 'Rubik'; font-size: 0.85rem; color: #94a3b8;">{date_str} • <b style="color: #e2e8f0;">{row['source']}</b></div>
            <div style="display: flex; gap: 10px;">
                <div style="background: {badge_bg}; color: {badge_color}; border: 1px solid {border_color}; padding: 2px 10px; border-radius: 99px; font-size: 0.75rem; font-weight: bold;">{row['severity'].upper()}</div>
                <div style="background: rgba(30, 41, 59, 0.5); color: #94a3b8; border: 1px solid #334155; padding: 2px 10px; border-radius: 99px; font-size: 0.75rem;">{row.get('tags', 'General')}</div>
                {raw_badge}
            </div>
        </div>
        <div dir="auto" style="font-size: 1.25rem; font-weight: 700; color: #f1f5f9; margin-bottom: 12px;">{row['title']}</div>
        <div dir="auto" style="font-size: 0.95rem; color: #cbd5e1; margin-bottom: 15px; opacity: 0.9; line-height: 1.6;">{summary}</div>
        <div style="text-align: right;"><a href="{row['url']}" target="_blank" style="color: #38bdf8; text-decoration: none; font-size: 0.85rem; padding: 5px 10px; background: rgba(56, 189, 248, 0.1); border-radius: 6px;">Open source 🔗</a></div>
    </div>
    """

init_db()
IL_TZ = pytz.timezone('Asia/Jerusalem')

GROQ_KEY = get_secret("groq_key", "")
VT_KEY = get_secret("vt_key", "")
URLSCAN_KEY = get_secret("urlscan_key", "")
ABUSE_KEY = get_secret("abuseipdb_key", "")

if 'last_run' not in st.session_state:
    st.session_state['last_run'] = time.time()
if time.time() - st.session_state['last_run'] > 900:
    st.session_state['last_run'] = time.time()
    st.rerun()

async def perform_update(status_container=None):
    col, proc = CTICollector(), AIBatchProcessor(GROQ_KEY)
    if status_container: status_container.markdown(":blue[**📡 Connecting to feeds...**]")
    raw, source_status = await col.get_all_data()
    st.session_state['source_status'] = source_status

    existing_urls, _ = get_existing_data()
    raw_to_process = [r for r in raw if r['url'] not in existing_urls]

    if raw_to_process:
        if status_container: status_container.markdown(f":orange[**🤖 Analyzing {len(raw_to_process)} new items...**]")
        results = await proc.analyze_batch(raw_to_process)
        return save_reports(raw_to_process, results)
    return 0

if "booted" not in st.session_state:
    with st.status("🚀 **Initializing system...**", expanded=True) as status:
        st.markdown(":green[**🔍 Running sanity check...**]")
        time.sleep(0.5)
        count = asyncio.run(perform_update(status))
        if count > 0: st.markdown(f":green[**✅ Ingested {count} new events.**]")
        else: st.markdown(":grey[**✅ System up to date.**]")
        status.update(label="✅ **System ready**", state="complete", expanded=False)
        time.sleep(1)
    st.session_state['booted'] = True
    st.rerun()

with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/9203/9203726.png", width=60)
    st.markdown("### CTI WAR ROOM")
    ok, msg = ConnectionManager.check_groq(GROQ_KEY)
    st.caption(f"AI STATUS: {msg}")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("⚡ Sync"):
            with st.status("🔄 **Syncing...**") as s:
                c = asyncio.run(perform_update(s))
                s.update(label=f"✅ Updated: {c}", state="complete")
            time.sleep(1)
            st.rerun()
    with col2:
        if st.button("🗑️ Reset"):
            try:
                if os.path.exists(DB_NAME):
                    os.remove(DB_NAME)
                    st.toast("✅ Cleared!", icon="🗑️")
                    time.sleep(1)
                    st.rerun()
            except Exception as e: st.error(f"Error: {e}")

    # --- Capability banner: surface missing keys instead of a silent no-op ---
    _caps = [("Groq (AI analysis)", GROQ_KEY), ("VirusTotal", VT_KEY), ("URLScan", URLSCAN_KEY), ("AbuseIPDB", ABUSE_KEY)]
    _missing = [name for name, val in _caps if not val]
    if _missing:
        st.warning("⚠️ Missing keys — disabled: " + ", ".join(_missing))

    # --- Source health from the last sync ---
    _statuses = st.session_state.get('source_status')
    if _statuses:
        _failed = [s for s in _statuses if not s['ok']]
        _ok_n = len(_statuses) - len(_failed)
        with st.expander(f"📡 Sources: {_ok_n}/{len(_statuses)} active", expanded=bool(_failed)):
            for s in _statuses:
                if s['ok']:
                    st.caption(f"✅ {s['source']} — {s['count']} items")
                else:
                    st.caption(f"❌ {s['source']} — {s.get('error', 'error')}")

st.title("Operations Dashboard")
conn = sqlite3.connect(DB_NAME)
c = conn.cursor()
c.execute(f"SELECT COUNT(*) FROM intel_reports WHERE published_at > datetime('now', '-{HISTORY_DAYS} days') AND source != 'DeepWeb'")
try: count_24h = c.fetchone()[0]
except Exception as e:
    log.warning("count_24h query failed: %s", e); count_24h = 0
c.execute(f"SELECT COUNT(*) FROM intel_reports WHERE severity LIKE '%Critical%' AND published_at > datetime('now', '-{HISTORY_DAYS} days')")
try: count_crit = c.fetchone()[0]
except Exception as e:
    log.warning("count_crit query failed: %s", e); count_crit = 0
conn.close()

m1, m2, m3, m4 = st.columns(4)
m1.metric(f"Reports ({HISTORY_DAYS}d)", count_24h)
m2.metric("Critical alerts", count_crit)
_src = st.session_state.get('source_status') or []
if _src:
    _src_ok = sum(1 for s in _src if s['ok'])
    m3.metric("Active sources", f"{_src_ok}/{len(_src)}")
    m4.metric("Source availability", f"{round(100 * _src_ok / len(_src))}%")
else:
    m3.metric("Sources", str(len(CTICollector.SOURCES)))
    m4.metric("Availability", "—")

st.markdown("---")

tab_feed, tab_strat, tab_tools, tab_map = st.tabs(["🔴 Live Feed", "🗂️ Threat Actors", "🛠️ Investigation Lab", "🌍 Attack Map"])

with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM intel_reports WHERE source != 'DeepWeb' ORDER BY published_at DESC LIMIT 200", conn)
    conn.close()
    if not df.empty:
        df['published_at'] = pd.to_datetime(df['published_at'], errors='coerce')
        df = df.sort_values(by='published_at', ascending=False).drop_duplicates(subset=['url'])
        c1, c2 = st.columns(2)
        with c1:
            all_tags = ['All', 'Phishing', 'Malware', 'Vulnerabilities', 'Israel', 'Research', 'General']
            f_tag = st.radio("Filter by tag", all_tags, horizontal=True)
        with c2:
            f_sev = st.radio("Severity", ["All", "Critical/High", "Medium", "Low/Info"], horizontal=True)
        if f_tag != 'All': df = df[df['tags'] == f_tag]
        if "High" in f_sev: df = df[df['severity'].str.contains('Critical|High', case=False)]
        for _, row in df.iterrows():
            try:
                dt = row['published_at']
                if pd.isnull(dt): date_display = "unknown date"
                else:
                    if dt.tzinfo is None: dt = pytz.utc.localize(dt).astimezone(IL_TZ)
                    else: dt = dt.astimezone(IL_TZ)
                    date_display = dt.strftime('%d/%m %H:%M')
            except Exception as e:
                log.debug("feed row date render failed: %s", e)
                date_display = "--/--"
            st.markdown(get_feed_card_html(row, date_display), unsafe_allow_html=True)
    else: st.info("No data yet. The system is collecting intel...")

with tab_strat:
    threats = APTSheetCollector().fetch_threats()
    sel = st.selectbox("Select group", [t['name'] for t in threats])
    actor = next(t for t in threats if t['name'] == sel)
    if st.button(f"🔎 Deep Web scan — {actor['name']}"):
        with st.status("🕵️ **Running collection agent...**", expanded=True) as s:
            scanner = DeepWebScanner()
            proc = AIBatchProcessor(GROQ_KEY)
            res = scanner.scan_actor(actor['name'], limit=3)
            if res:
                s.markdown(":orange[**Indicators found, analyzing...**]")
                analyzed = asyncio.run(proc.analyze_batch(res))
                to_save = [r for r in res if r['url'] not in get_existing_data()[0]]
                if to_save:
                    save_reports(to_save, analyzed)
                    st.success(f"Added {len(to_save)} new reports!")
                else: st.info("Already in the system.")
            else: st.warning("No new results.")
            st.rerun()
    st.markdown(f"""
    <div style="background:linear-gradient(180deg, rgba(30, 41, 59, 0.6) 0%, rgba(15, 23, 42, 0.8) 100%); padding:20px; border-radius:10px; border-left:4px solid #f59e0b;">
        <h2 style="color:white; margin:0;">{actor['name']}</h2>
        <p style="color:#cbd5e1; font-size:1.1rem;">{actor['desc']}</p>
        <div style="display:flex; gap:10px; margin-top:10px;">
            <span style="background:#0f172a; padding:5px 10px; border-radius:5px; color:#fcd34d;">Origin: {actor['origin']}</span>
            <span style="background:#0f172a; padding:5px 10px; border-radius:5px; color:#fbcfe8;">Target: {actor['target']}</span>
            <span style="background:#0f172a; padding:5px 10px; border-radius:5px; color:#93c5fd;">Type: {actor['type']}</span>
        </div>
        <hr style="border-color:#334155;">
        <p><b>Tools:</b> <code style="color:#fca5a5;">{actor['tools']}</code></p>
    </div>
    """, unsafe_allow_html=True)
    conn = sqlite3.connect(DB_NAME)
    df_deep = pd.read_sql_query(f"SELECT * FROM intel_reports WHERE source = 'DeepWeb' AND actor_tag = '{actor['name']}' ORDER BY published_at DESC LIMIT 10", conn)
    conn.close()
    st.markdown("##### 🕵️ Scan history")
    if not df_deep.empty:
        for _, row in df_deep.iterrows():
            st.markdown(get_feed_card_html(row, "Deep Web Hit"), unsafe_allow_html=True)
    else: st.info("No history available.")

with tab_tools:
    st.markdown("#### 🛠️ Toolkit")
    toolkit = AnalystToolkit.get_tools()
    c1, c2, c3 = st.columns(3)
    cols = [c1, c2, c3]
    for i, (category, tools) in enumerate(toolkit.items()):
        with cols[i]:
            st.markdown(f"**{category}**")
            for tool in tools:
                st.markdown(f"""<a href="{tool['url']}" target="_blank"><div class="tool-card"><span class="tool-icon">{tool['icon']}</span><span class="tool-name">{tool['name']}</span><span class="tool-desc">{tool['desc']}</span></div></a>""", unsafe_allow_html=True)
    st.markdown("---")
    st.markdown("#### 🔬 IOC Investigation")
    if 'scan_res' not in st.session_state: st.session_state['scan_res'] = None
    ioc_in = st.text_input("Enter indicator (IP / URL / Hash)", key="ioc_input")
    if st.button("Investigate"):
        st.session_state['scan_res'] = None
        itype = identify_ioc_type(ioc_in)
        if itype:
            tl = ThreatLookup(VT_KEY, URLSCAN_KEY, ABUSE_KEY)
            with st.spinner("Gathering intel from engines..."):
                vt = tl.query_virustotal(ioc_in, itype)
                us = tl.query_urlscan(ioc_in)
                ab = tl.query_abuseipdb(ioc_in) if itype == 'ip' else None
                ai_res = asyncio.run(AIBatchProcessor(GROQ_KEY).analyze_single_ioc(ioc_in, itype, {'virustotal': vt, 'urlscan': us}))
                st.session_state['scan_res'] = {'vt': vt, 'us': us, 'ab': ab, 'ai': ai_res, 'type': itype}
        else:
            st.warning("Unrecognized indicator. Enter an IP, URL, domain, or hash.")
    res = st.session_state.get('scan_res')
    if res:
        vt, us, ab = res['vt'], res['us'], res['ab']
        if us and us.get('task') and us.get('page'):
            if us['task'].get('url') != us['page'].get('url'):
                st.markdown(f"""<div class="redirect-alert">⚠️ Redirect detected!<br>From: {us['task'].get('url')}<br>Final: {us['page'].get('url')}</div>""", unsafe_allow_html=True)
        c1, c2, c3 = st.columns(3)
        if vt:
            mal = vt.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
            c1.markdown(f"""<div class="ioc-card {'ioc-danger' if mal > 0 else 'ioc-safe'}"><div class="ioc-title">VirusTotal</div><div class="ioc-value">{mal}</div><div class="ioc-sub">Malicious Hits</div></div>""", unsafe_allow_html=True)
        else: c1.markdown("""<div class="ioc-card ioc-neutral"><div class="ioc-title">VirusTotal</div><div class="ioc-value">N/A</div></div>""", unsafe_allow_html=True)
        if ab:
            score = ab.get('abuseConfidenceScore', 0)
            c2.markdown(f"""<div class="ioc-card {'ioc-danger' if score > 50 else 'ioc-safe'}"><div class="ioc-title">AbuseIPDB</div><div class="ioc-value">{score}%</div><div class="ioc-sub">Confidence</div></div>""", unsafe_allow_html=True)
        else: c2.markdown("""<div class="ioc-card ioc-neutral"><div class="ioc-title">AbuseIPDB</div><div class="ioc-value">IP Only</div></div>""", unsafe_allow_html=True)
        if us: c3.markdown("""<div class="ioc-card ioc-safe"><div class="ioc-title">URLScan</div><div class="ioc-value">Found</div><div class="ioc-sub">View Details</div></div>""", unsafe_allow_html=True)
        else: c3.markdown("""<div class="ioc-card ioc-neutral"><div class="ioc-title">URLScan</div><div class="ioc-value">N/A</div></div>""", unsafe_allow_html=True)
        t1, t2, t3, t4 = st.tabs(["🤖 AI Analysis", "🦠 Technical (VT)", "📷 URLScan", "🚫 AbuseIPDB"])
        with t1: st.markdown(f'<div dir="auto">{res["ai"]}</div>', unsafe_allow_html=True)
        with t2:
             if vt: st.json(vt.get('attributes', {}).get('last_analysis_stats'))
             else: st.info("No data.")
        with t3:
             if us: st.image(us.get('task', {}).get('screenshotURL'))
             else: st.info("No data.")
        with t4:
            if ab: st.metric("Total Reports", ab.get('totalReports'))
            else: st.info("IP only.")

with tab_map:
    components.iframe("https://threatmap.checkpoint.com/", height=700)

st.markdown("""<div class="footer">SYSTEM ARCHITECT: <b>LIDOR AVRAHAMY</b></div>""", unsafe_allow_html=True)
