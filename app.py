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

# --- CSS STYLING ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Rubik:wght@300;400;600&family=Heebo:wght@300;400;700&display=swap');
    
    .stApp { direction: rtl; text-align: right; background-color: #0b0f19; font-family: 'Heebo', sans-serif; }
    h1, h2, h3, h4, h5, h6, p, div, span, label, .stMarkdown { text-align: right; font-family: 'Heebo', sans-serif; }
    
    /* Move Sidebar Toggle to Left (RTL Fix) */
    [data-testid="stSidebarCollapseButton"] {
        float: left;
        margin-left: 10px;
        margin-right: auto;
    }
    
    /* Widget Alignments */
    .stTextInput input, .stSelectbox, .stMultiSelect { direction: rtl; text-align: right; }
    .stButton button { width: 100%; font-family: 'Rubik', sans-serif; border-radius: 8px; }
    .stTabs [data-baseweb="tab-list"] { justify-content: flex-end; gap: 15px; }
    
    /* Tool Cards */
    .tool-card {
        background: rgba(30, 41, 59, 0.7);
        border: 1px solid rgba(56, 189, 248, 0.3);
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        margin-bottom: 15px;
        height: 100%;
        color: white;
        cursor: pointer;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    }
    .tool-card:hover {
        background: rgba(56, 189, 248, 0.2);
        border-color: #38bdf8;
        transform: translateY(-4px);
        box-shadow: 0 10px 15px -3px rgba(56, 189, 248, 0.2), 0 4px 6px -2px rgba(56, 189, 248, 0.1);
    }
    .tool-icon { font-size: 32px; margin-bottom: 10px; display: block; filter: drop-shadow(0 0 5px rgba(255,255,255,0.3)); }
    .tool-name { font-weight: 700; color: #f1f5f9; display: block; margin-bottom: 5px; font-size: 1.1rem; }
    .tool-desc { font-size: 0.85rem; color: #cbd5e1; display: block; line-height: 1.4; }
    a { text-decoration: none; }

    /* Report Cards */
    .report-card {
        background: rgba(30, 41, 59, 0.4); backdrop-filter: blur(12px);
        border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 12px; padding: 24px; margin-bottom: 20px;
    }

    /* IOC Score Cards */
    .ioc-card {
        padding: 15px; border-radius: 10px; text-align: center; color: white; margin-bottom: 10px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .ioc-safe { background: linear-gradient(135deg, #10b981, #059669); }
    .ioc-danger { background: linear-gradient(135deg, #ef4444, #b91c1c); }
    .ioc-neutral { background: linear-gradient(135deg, #64748b, #475569); }
    .ioc-title { font-size: 0.9rem; font-weight: bold; opacity: 0.9; }
    .ioc-value { font-size: 1.8rem; font-weight: bold; margin: 5px 0; }
    .ioc-sub { font-size: 0.8rem; opacity: 0.8; }
    
    /* Redirect Alert */
    .redirect-alert {
        background: rgba(245, 158, 11, 0.2); border: 1px solid #f59e0b; color: #fcd34d;
        padding: 15px; border-radius: 8px; margin-bottom: 15px;
        display: flex; align-items: center; gap: 10px; font-weight: bold;
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
    summary = clean_html(row['summary']).replace('\n', '<br>')
    
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
        <div style="font-size: 0.95rem; color: #cbd5e1; margin-bottom: 15px; opacity: 0.9; line-height: 1.6;">{summary}</div>
        <div style="text-align: left;">
            <a href="{row['url']}" target="_blank" style="display: inline-flex; align-items: center; gap: 5px; color: #38bdf8; text-decoration: none; font-size: 0.85rem; padding: 5px 10px; background: rgba(56, 189, 248, 0.1); border-radius: 6px;">
                פתח מקור 🔗
            </a>
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

if "booted" not in st.session_state:
    st.markdown("<h3 style='text-align:center;'>🚀 טוען מערכת מודיעין...</h3>", unsafe_allow_html=True)
    asyncio.run(perform_update())
    threats = APTSheetCollector().fetch_threats()
    scanner = DeepWebScanner()
    proc = AIBatchProcessor(GROQ_KEY)
    for threat in threats:
        res = scanner.scan_actor(threat['name'], limit=2)
        if res:
             analyzed = asyncio.run(proc.analyze_batch(res))
             save_reports(res, analyzed)
    st.session_state['booted'] = True
    st.rerun()

# --- SIDEBAR ---
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

tab_feed, tab_strat, tab_tools, tab_map = st.tabs(["🔴 עדכונים שוטפים", "🗂️ תיקי תקיפה", "🛠️ מעבדת חקירות", "🌍 מפת תקיפות"])

# --- TAB 1: LIVE FEED ---
with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    df_incd = pd.read_sql_query("SELECT * FROM intel_reports WHERE source = 'INCD' ORDER BY published_at DESC LIMIT 10", conn)
    df_rest = pd.read_sql_query("SELECT * FROM intel_reports WHERE source != 'INCD' AND source != 'DeepWeb' AND published_at > datetime('now', '-2 days') ORDER BY published_at DESC LIMIT 50", conn)
    conn.close()
    
    df = pd.concat([df_incd, df_rest])
    df['published_at'] = pd.to_datetime(df['published_at'], errors='coerce')
    df = df.sort_values(by='published_at', ascending=False).drop_duplicates(subset=['url'])
    
    c1, c2 = st.columns(2)
    with c1: 
        all_tags = ['הכל', 'פיישינג', 'נוזקה', 'פגיעויות', 'ישראל', 'מחקר', 'כללי']
        f_tag = st.radio("סינון לפי תגיות", all_tags, horizontal=True)
    with c2: 
        f_sev = st.radio("חומרה", ["הכל", "קריטי/גבוה", "בינוני", "נמוך/מידע"], horizontal=True)
    
    if f_tag != 'הכל': df = df[df['tags'] == f_tag]
    if "גבוה" in f_sev: df = df[df['severity'].str.contains('Critical|High', case=False)]
    
    for _, row in df.iterrows():
        try:
            dt = row['published_at']
            if pd.isnull(dt): date_display = "תאריך לא ידוע"
            else:
                if dt.tzinfo is None: dt = pytz.utc.localize(dt).astimezone(IL_TZ)
                else: dt = dt.astimezone(IL_TZ)
                date_display = dt.strftime('%d/%m %H:%M')
        except: date_display = "--/--"
        
        st.markdown(get_feed_card_html(row, date_display), unsafe_allow_html=True)

# --- TAB 2: DOSSIER ---
with tab_strat:
    threats = APTSheetCollector().fetch_threats()
    sel = st.selectbox("בחר קבוצה", [t['name'] for t in threats])
    actor = next(t for t in threats if t['name'] == sel)
    
    st.markdown(f"""
    <div style="background:linear-gradient(180deg, rgba(30, 41, 59, 0.6) 0%, rgba(15, 23, 42, 0.8) 100%); padding:20px; border-radius:10px; border-left:4px solid #f59e0b; direction:rtl; text-align:right;">
        <h2 style="color:white; margin:0;">{actor['name']}</h2>
        <p style="color:#cbd5e1; font-size:1.1rem;">{actor['desc']}</p>
        <div style="display:flex; gap:10px; margin-top:10px;">
            <span style="background:#0f172a; padding:5px 10px; border-radius:5px; color:#fcd34d;">מוצא: {actor['origin']}</span>
            <span style="background:#0f172a; padding:5px 10px; border-radius:5px; color:#fbcfe8;">יעד: {actor['target']}</span>
            <span style="background:#0f172a; padding:5px 10px; border-radius:5px; color:#93c5fd;">סוג: {actor['type']}</span>
        </div>
        <hr style="border-color:#334155;">
        <p><b>כלים:</b> <code style="color:#fca5a5;">{actor['tools']}</code></p>
    </div>
    """, unsafe_allow_html=True)
    
    conn = sqlite3.connect(DB_NAME)
    df_deep = pd.read_sql_query(f"SELECT * FROM intel_reports WHERE source = 'DeepWeb' AND actor_tag = '{actor['name']}' ORDER BY published_at DESC LIMIT 10", conn)
    conn.close()
    
    st.markdown("##### 🕵️ ממצאי Deep Scan (אוטומטי)")
    if not df_deep.empty:
        for _, row in df_deep.iterrows():
            st.markdown(get_feed_card_html(row, "Deep Web Hit"), unsafe_allow_html=True)
    else:
        st.info("לא נמצאו ממצאים חדשים בסריקה האחרונה.")

# --- TAB 3: TOOLS & LAB ---
with tab_tools:
    st.markdown("#### 🛠️ ארגז כלים")
    toolkit = AnalystToolkit.get_tools()
    
    c1, c2, c3 = st.columns(3)
    cols = [c1, c2, c3]
    for i, (category, tools) in enumerate(toolkit.items()):
        with cols[i]:
            st.markdown(f"**{category}**")
            for tool in tools:
                st.markdown(f"""
                <a href="{tool['url']}" target="_blank">
                    <div class="tool-card">
                        <span class="tool-icon">{tool['icon']}</span>
                        <span class="tool-name">{tool['name']}</span>
                        <span class="tool-desc">{tool['desc']}</span>
                    </div>
                </a>
                """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### 🔬 חקירת IOC")
    
    if 'scan_res' not in st.session_state: st.session_state['scan_res'] = None
    
    ioc_in = st.text_input("הזן אינדיקטור (IP/URL/Hash)", key="ioc_input")
    if st.button("בצע חקירה"):
        st.session_state['scan_res'] = None 
        itype = identify_ioc_type(ioc_in)
        if itype:
            tl = ThreatLookup(VT_KEY, URLSCAN_KEY, ABUSE_KEY)
            with st.spinner("אוסף מודיעין ממנועים..."):
                vt = tl.query_virustotal(ioc_in, itype)
                us = tl.query_urlscan(ioc_in)
                ab = tl.query_abuseipdb(ioc_in) if itype == 'ip' else None
                ai_res = asyncio.run(AIBatchProcessor(GROQ_KEY).analyze_single_ioc(ioc_in, itype, {'virustotal': vt, 'urlscan': us}))
                
                st.session_state['scan_res'] = {'vt': vt, 'us': us, 'ab': ab, 'ai': ai_res, 'type': itype}

    # RESULTS
    res = st.session_state.get('scan_res')
    if res:
        vt, us, ab = res['vt'], res['us'], res['ab']
        
        # --- REDIRECT ALERT ---
        if us and us.get('task') and us.get('page'):
            input_url = us['task'].get('url', '')
            final_url = us['page'].get('url', '')
            if input_url != final_url:
                st.markdown(f"""
                <div class="redirect-alert">
                    ⚠️ זוהתה הפנייה (Redirect)!
                    <br>מקור: {input_url}
                    <br>יעד סופי: {final_url}
                </div>
                """, unsafe_allow_html=True)

        # 1. SCORE CARDS
        c1, c2, c3 = st.columns(3)
        
        # VT CARD
        if vt:
            mal = vt.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
            color_class = "ioc-danger" if mal > 0 else "ioc-safe"
            c1.markdown(f"""
            <div class="ioc-card {color_class}">
                <div class="ioc-title">VirusTotal</div>
                <div class="ioc-value">{mal}</div>
                <div class="ioc-sub">Malicious Hits</div>
            </div>
            """, unsafe_allow_html=True)
        else:
             c1.markdown("""<div class="ioc-card ioc-neutral"><div class="ioc-title">VirusTotal</div><div class="ioc-value">N/A</div></div>""", unsafe_allow_html=True)
        
        # ABUSEIPDB CARD
        if ab:
            score = ab.get('abuseConfidenceScore', 0)
            color_class = "ioc-danger" if score > 50 else "ioc-safe"
            c2.markdown(f"""
            <div class="ioc-card {color_class}">
                <div class="ioc-title">AbuseIPDB</div>
                <div class="ioc-value">{score}%</div>
                <div class="ioc-sub">Confidence</div>
            </div>
            """, unsafe_allow_html=True)
        elif res['type'] != 'ip':
             c2.markdown("""<div class="ioc-card ioc-neutral"><div class="ioc-title">AbuseIPDB</div><div class="ioc-value">IP Only</div></div>""", unsafe_allow_html=True)
        
        # URLSCAN CARD
        if us:
             c3.markdown("""<div class="ioc-card ioc-safe"><div class="ioc-title">URLScan</div><div class="ioc-value">Found</div><div class="ioc-sub">View Details</div></div>""", unsafe_allow_html=True)
        else:
             c3.markdown("""<div class="ioc-card ioc-neutral"><div class="ioc-title">URLScan</div><div class="ioc-value">N/A</div></div>""", unsafe_allow_html=True)

        # 2. DETAILS TABS
        t1, t2, t3, t4 = st.tabs(["🤖 ניתוח AI", "🦠 נתונים טכניים (VT)", "📷 URLScan", "🚫 AbuseIPDB"])
        
        with t1:
             st.markdown(f'<div style="direction:rtl; text-align:right;">{res["ai"]}</div>', unsafe_allow_html=True)
        
        with t2:
             if vt:
                attr = vt.get('attributes', {})
                st.write("**HTTP Response:**", attr.get('last_http_response_code'))
                st.write("**Last Analysis:**", datetime.datetime.fromtimestamp(attr.get('last_analysis_date', 0)).strftime('%Y-%m-%d'))
                st.write("**Categories:**", attr.get('categories'))
                st.write("**Tags:**", attr.get('tags'))
                st.json(attr.get('last_analysis_stats'))
             else: st.info("אין נתונים.")

        with t3:
             if us:
                task = us.get('task', {})
                page = us.get('page', {})
                st.image(task.get('screenshotURL'), caption="Screenshot")
                st.write(f"**Final URL:** {page.get('url')}")
                st.write(f"**Server:** {page.get('server')}")
                st.write(f"**Country:** {page.get('country')}")
                st.write(f"**IP:** {page.get('ip')}")
                with st.expander("Redirect Chain"):
                    st.json(us.get('data', {}).get('requests', []))
             else: st.info("אין נתונים.")

        with t4:
            if ab:
                st.write(f"**ISP:** {ab.get('isp')}")
                st.write(f"**Domain:** {ab.get('domain')}")
                st.write(f"**Usage Type:** {ab.get('usageType')}")
                st.write(f"**Country:** {ab.get('countryCode')}")
                st.metric("Total Reports", ab.get('totalReports'))
            else: st.info("רלוונטי ל-IP בלבד.")

with tab_map:
    components.iframe("https://threatmap.checkpoint.com/", height=700)

st.markdown("""<div class="footer">SYSTEM ARCHITECT: <b>LIDOR AVRAHAMY</b></div>""", unsafe_allow_html=True)
