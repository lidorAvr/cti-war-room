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

# --- HTML STYLES & RTL ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Rubik:wght@300;400;600&family=Heebo:wght@300;400;700&display=swap');
    
    .stApp { direction: rtl; text-align: right; background-color: #0b0f19; font-family: 'Heebo', sans-serif; }
    h1, h2, h3, h4, h5, h6, p, div, span, label, .stMarkdown { text-align: right; font-family: 'Heebo', sans-serif; }
    
    /* RTL Fixes */
    .stTextInput input, .stSelectbox, .stMultiSelect { direction: rtl; text-align: right; }
    .stButton button { width: 100%; font-family: 'Rubik', sans-serif; }
    .stTabs [data-baseweb="tab-list"] { justify-content: flex-end; gap: 15px; }
    
    /* Live Feed Card */
    .report-card {
        background: rgba(30, 41, 59, 0.4); backdrop-filter: blur(12px);
        border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 12px; padding: 24px; margin-bottom: 20px;
    }
    
    /* Dossier Rich Card */
    .dossier-card {
        border-left: 4px solid #f59e0b; 
        background: linear-gradient(180deg, rgba(30, 41, 59, 0.6) 0%, rgba(15, 23, 42, 0.8) 100%);
        padding: 24px; border-radius: 12px; margin-bottom: 20px; direction: ltr; /* English text for Dossier */
    }
    
    /* Footer */
    .footer {
        position: fixed; left: 0; bottom: 0; width: 100%;
        background: rgba(15, 23, 42, 0.95); border-top: 1px solid #1e293b;
        color: #64748b; text-align: center; padding: 10px; font-size: 0.75rem; direction: ltr; z-index: 999;
    }
</style>
""", unsafe_allow_html=True)

def clean_html(raw_html):
    cleanr = re.compile('<.*?>')
    return re.sub(cleanr, '', str(raw_html)).replace('"', '&quot;').strip()

def get_feed_card_html(row, date_str):
    sev = row['severity'].lower()
    badge_bg, badge_color, border_color = "rgba(100, 116, 139, 0.2)", "#cbd5e1", "rgba(100, 116, 139, 0.3)"
    
    if "critical" in sev or "high" in sev:
        badge_bg, badge_color, border_color = "rgba(220, 38, 38, 0.2)", "#fca5a5", "#ef4444"
    elif "medium" in sev:
        badge_bg, badge_color, border_color = "rgba(59, 130, 246, 0.2)", "#93c5fd", "#3b82f6"
        
    source_display = f"🇮🇱 {row['source']}" if row['source'] == 'INCD' else f"📡 {row['source']}"
    tag_display = row.get('tags', 'כללי')
    
    return f"""
    <div class="report-card" style="direction: rtl; text-align: right; border-right: 4px solid {border_color};">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-direction: row-reverse;">
             <div style="display: flex; gap: 10px;">
                <div style="background: {badge_bg}; color: {badge_color}; border: 1px solid {border_color}; padding: 2px 10px; border-radius: 99px; font-size: 0.75rem; font-weight: bold;">
                    {row['severity'].upper()}
                </div>
                <div style="background: rgba(30, 41, 59, 0.5); color: #94a3b8; border: 1px solid #334155; padding: 2px 10px; border-radius: 99px; font-size: 0.75rem;">
                    {tag_display}
                </div>
             </div>
            <div style="font-family: 'Rubik'; font-size: 0.85rem; color: #94a3b8;">
                {date_str} • <b style="color: #e2e8f0;">{source_display}</b>
            </div>
        </div>
        <div style="font-size: 1.25rem; font-weight: 700; color: #f1f5f9; margin-bottom: 12px;">{row['title']}</div>
        <div style="font-size: 0.95rem; color: #cbd5e1; margin-bottom: 15px; opacity: 0.9;">{clean_html(row['summary'])}</div>
        <div style="text-align: left;">
            <a href="{row['url']}" target="_blank" style="display: inline-flex; align-items: center; gap: 5px; color: #38bdf8; text-decoration: none; font-size: 0.85rem; padding: 5px 10px; background: rgba(56, 189, 248, 0.1); border-radius: 6px;">
                פתח מקור 🔗
            </a>
        </div>
    </div>
    """

def get_dossier_html(actor):
    # Richer Design Restored
    return f"""
    <div class="dossier-card">
        <h2 style="margin-top:0; color: #ffffff; font-size: 2rem; letter-spacing: -1px; text-align: left;">{actor['name']}</h2>
        <div style="margin-bottom: 25px; display: flex; gap: 10px; flex-wrap: wrap; justify-content: flex-start;">
            <span style="background: rgba(59, 130, 246, 0.15); color: #93c5fd; padding: 4px 12px; border-radius: 99px; font-size: 0.8rem; border: 1px solid rgba(59, 130, 246, 0.3);">ORIGIN: {actor['origin']}</span>
            <span style="background: rgba(245, 158, 11, 0.15); color: #fcd34d; padding: 4px 12px; border-radius: 99px; font-size: 0.8rem; border: 1px solid rgba(245, 158, 11, 0.3);">TARGET: {actor['target']}</span>
            <span style="background: rgba(236, 72, 153, 0.15); color: #fbcfe8; padding: 4px 12px; border-radius: 99px; font-size: 0.8rem; border: 1px solid rgba(236, 72, 153, 0.3);">TYPE: {actor['type']}</span>
        </div>
        <p style="font-size: 1.1rem; color: #e2e8f0; margin-bottom: 30px; line-height: 1.6; border-bottom: 1px solid #334155; padding-bottom: 20px; text-align: left;">
            {actor['desc']}
        </p>
        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; text-align: left;">
            <div style="background: rgba(15, 23, 42, 0.5); padding: 15px; border-radius: 8px; border: 1px solid #334155;">
                <h5 style="color: #94a3b8; margin-top: 0; font-size: 0.85rem; text-transform: uppercase;">🛠️ Known Tools</h5>
                <code style="color: #fca5a5; background: transparent;">{actor['tools']}</code>
            </div>
            <div style="background: rgba(15, 23, 42, 0.5); padding: 15px; border-radius: 8px; border: 1px solid #334155;">
                <h5 style="color: #94a3b8; margin-top: 0; font-size: 0.85rem; text-transform: uppercase;">📚 MITRE TTPs</h5>
                <code style="color: #fcd34d; background: transparent;">{actor['mitre']}</code>
            </div>
        </div>
    </div>
    """

# --- INITIALIZATION ---
init_db() 
IL_TZ = pytz.timezone('Asia/Jerusalem')
st_autorefresh(interval=15 * 60 * 1000, key="data_refresh")

GROQ_KEY = st.secrets.get("groq_key", "")
VT_KEY = st.secrets.get("vt_key", "")
URLSCAN_KEY = st.secrets.get("urlscan_key", "")
ABUSE_KEY = st.secrets.get("abuseipdb_key", "")

async def perform_update():
    col, proc = CTICollector(), AIBatchProcessor(GROQ_KEY)
    raw = await col.get_all_data()
    if raw:
        analyzed = await proc.analyze_batch(raw)
        return save_reports(raw, analyzed)
    return 0

# --- AUTO BOOT SEQUENCE ---
if "booted" not in st.session_state:
    st.markdown("<h3 style='text-align:center;'>🚀 מערכת עולה... מבצע סריקת מודיעין ראשונית</h3>", unsafe_allow_html=True)
    
    # Run Standard Feeds
    asyncio.run(perform_update())
    
    # Auto Run Deep Scan for ALL actors (Background)
    threats = APTSheetCollector().fetch_threats()
    scanner = DeepWebScanner()
    proc = AIBatchProcessor(GROQ_KEY)
    for threat in threats:
        # Quick scan 2 items per actor to populate
        res = scanner.scan_actor(threat['name'], limit=2)
        if res:
             analyzed = asyncio.run(proc.analyze_batch(res))
             save_reports(res, analyzed)
             
    st.session_state['booted'] = True
    st.rerun()

# --- SIDEBAR & HEADER ---
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/9203/9203726.png", width=60)
    st.markdown("### CTI WAR ROOM")
    ok, msg = ConnectionManager.check_groq(GROQ_KEY)
    st.caption(f"AI STATUS: {msg}")
    if st.button("⚡ סנכרון ידני"):
        count = asyncio.run(perform_update())
        st.success(f"עודכן: {count}")
        time.sleep(1)
        st.rerun()

st.title("לוח בקרה מבצעי")
conn = sqlite3.connect(DB_NAME)
c = conn.cursor()
c.execute("SELECT COUNT(*) FROM intel_reports WHERE published_at > datetime('now', '-24 hours') AND source != 'DeepWeb'")
count_24h = c.fetchone()[0]
c.execute("SELECT COUNT(*) FROM intel_reports WHERE severity LIKE '%Critical%' AND published_at > datetime('now', '-24 hours')")
count_crit = c.fetchone()[0]
conn.close()

m4, m3, m2, m1 = st.columns(4)
m1.metric("ידיעות (24ש)", count_24h)
m2.metric("התרעות קריטיות", count_crit)
m3.metric("מקורות", "7")
m4.metric("זמינות", "100%")

st.markdown("---")

# --- TABS ---
tab_feed, tab_strat, tab_tools, tab_map = st.tabs(["🔴 עדכונים שוטפים", "🗂️ תיקי תקיפה", "🛠️ מעבדת חקירות", "🌍 מפת תקיפות"])

with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    # 1. Fetch Top 4 INCD (Always)
    df_incd = pd.read_sql_query("SELECT * FROM intel_reports WHERE source = 'INCD' ORDER BY published_at DESC LIMIT 4", conn)
    # 2. Fetch Others (Time restricted)
    df_rest = pd.read_sql_query("SELECT * FROM intel_reports WHERE source != 'INCD' AND source != 'DeepWeb' AND published_at > datetime('now', '-2 days') ORDER BY published_at DESC LIMIT 50", conn)
    conn.close()
    
    df = pd.concat([df_incd, df_rest]).sort_values(by='published_at', ascending=False).drop_duplicates(subset=['url'])
    
    c1, c2 = st.columns(2)
    with c1: 
        # TAG FILTER
        all_tags = ['הכל', 'פיישינג', 'נוזקה', 'פגיעויות', 'ישראל', 'מחקר', 'כללי']
        f_tag = st.radio("סינון לפי תגיות", all_tags, horizontal=True)
    with c2: 
        # SEVERITY FILTER (4 Levels)
        f_sev = st.radio("חומרה", ["הכל", "קריטי/גבוה", "בינוני", "נמוך/מידע"], horizontal=True)
    
    # Apply Tag Filter
    if f_tag != 'הכל':
        df = df[df['tags'] == f_tag]
    
    # Apply Severity Filter
    if "גבוה" in f_sev: df = df[df['severity'].str.contains('Critical|High', case=False)]
    elif "בינוני" in f_sev: df = df[df['severity'].str.contains('Medium', case=False)]
    elif "נמוך" in f_sev: df = df[df['severity'].str.contains('Low|Info', case=False)]

    if df.empty:
        st.info("לא נמצאו ידיעות התואמות את הסינון.")
    
    for _, row in df.iterrows():
        # Clean Date Format
        try:
            dt_obj = date_parser.parse(row['published_at'])
            if dt_obj.tzinfo is None: dt_obj = pytz.utc.localize(dt_obj).astimezone(IL_TZ)
            else: dt_obj = dt_obj.astimezone(IL_TZ)
            date_display = dt_obj.strftime('%d/%m %H:%M')
        except: date_display = row['published_at']
        
        st.markdown(get_feed_card_html(row, date_display), unsafe_allow_html=True)

with tab_strat:
    threats = APTSheetCollector().fetch_threats()
    sel = st.selectbox("בחר קבוצה", [t['name'] for t in threats])
    actor = next(t for t in threats if t['name'] == sel)
    st.markdown(get_dossier_html(actor), unsafe_allow_html=True)
    
    st.markdown("---")
    st.markdown(f"##### 🕵️ תוצאות סריקת עומק (Deep Scan) - {actor['name']}")
    
    # Fetch Deep Web Results for this Actor
    conn = sqlite3.connect(DB_NAME)
    df_deep = pd.read_sql_query(f"SELECT * FROM intel_reports WHERE source = 'DeepWeb' AND actor_tag = '{actor['name']}' ORDER BY published_at DESC LIMIT 10", conn)
    conn.close()
    
    if not df_deep.empty:
        for _, row in df_deep.iterrows():
            st.markdown(get_feed_card_html(row, "Deep Web Hit"), unsafe_allow_html=True)
    else:
        st.info("לא נמצאו ממצאים חדשים בסריקה האחרונה.")

with tab_tools:
    st.markdown("#### 🛠️ קיצורי דרך לאנליסטים")
    # RESTORED TOOLKIT SHORTCUTS
    toolkit = AnalystToolkit.get_tools()
    cols = st.columns(3)
    i = 0
    for category, tools in toolkit.items():
        with cols[i % 3]:
            st.markdown(f"**{category}**")
            for tool in tools:
                st.markdown(f"• [{tool['name']}]({tool['url']}) - {tool['desc']}")
        i += 1
        
    st.markdown("---")
    st.markdown("#### 🔬 חקירת IOC")
    ioc_in = st.text_input("הזן אינדיקטור (IP/URL/Hash)")
    if st.button("בצע חקירה") and ioc_in:
        itype = identify_ioc_type(ioc_in)
        if itype:
            tl = ThreatLookup(VT_KEY, URLSCAN_KEY, ABUSE_KEY)
            with st.spinner("מבצע סריקה במנועים..."):
                vt = tl.query_virustotal(ioc_in, itype)
                us = tl.query_urlscan(ioc_in)
                ab = tl.query_abuseipdb(ioc_in)
                
                # RESTORED 3-COLUMN METRICS
                c1, c2, c3 = st.columns(3)
                if vt: 
                    mal = vt.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                    c1.metric("VirusTotal", f"{mal} Hits", delta="Suspicious" if mal > 0 else "Clean", delta_color="inverse")
                else: c1.metric("VirusTotal", "N/A")
                
                if ab:
                    c2.metric("AbuseIPDB", f"{ab.get('abuseConfidenceScore', 0)}%", "Confidence")
                else: c2.metric("AbuseIPDB", "N/A")
                
                if us:
                    c3.metric("URLScan", "Completed", "View Report")
                else: c3.metric("URLScan", "N/A")
                
                # AI Analysis
                ai_res = asyncio.run(AIBatchProcessor(GROQ_KEY).analyze_single_ioc(ioc_in, itype, {'virustotal': vt}))
                st.markdown(ai_res)

with tab_map:
    components.iframe("https://threatmap.checkpoint.com/", height=700)

st.markdown("""<div class="footer">SYSTEM ARCHITECT: <b>LIDOR AVRAHAMY</b></div>""", unsafe_allow_html=True)
