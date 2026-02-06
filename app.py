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

st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Rubik:wght@300;400;600&family=Heebo:wght@300;400;700&display=swap');
    
    .stApp { direction: rtl; text-align: right; background-color: #0b0f19; font-family: 'Heebo', sans-serif; }
    h1, h2, h3, h4, h5, h6, p, div, span, label, .stMarkdown { text-align: right; font-family: 'Heebo', sans-serif; }
    
    /* Widget Alignments */
    .stTextInput input, .stSelectbox, .stMultiSelect { direction: rtl; text-align: right; }
    .stButton button { width: 100%; font-family: 'Rubik', sans-serif; border-radius: 8px; }
    .stTabs [data-baseweb="tab-list"] { justify-content: flex-end; gap: 15px; }
    
    /* Tool Cards */
    .tool-card {
        background: rgba(30, 41, 59, 0.6);
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 10px;
        padding: 15px;
        text-align: center;
        transition: all 0.2s;
        margin-bottom: 10px;
        height: 100%;
        color: white;
    }
    .tool-card:hover {
        background: rgba(56, 189, 248, 0.15);
        border-color: #38bdf8;
        transform: translateY(-2px);
    }
    .tool-icon { font-size: 24px; margin-bottom: 5px; display: block; }
    .tool-name { font-weight: bold; color: #e2e8f0; display: block; margin-bottom: 5px; }
    .tool-desc { font-size: 0.8rem; color: #94a3b8; display: block; }
    a { text-decoration: none; }

    /* Report Cards */
    .report-card {
        background: rgba(30, 41, 59, 0.4); backdrop-filter: blur(12px);
        border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 12px; padding: 24px; margin-bottom: 20px;
    }
    
    /* Footer */
    .footer {
        position: fixed; left: 0; bottom: 0; width: 100%;
        background: rgba(15, 23, 42, 0.95); border-top: 1px solid #1e293b;
        color: #64748b; text-align: center; padding: 10px; font-size: 0.75rem; direction: ltr; z-index: 999;
    }
    
    /* JSON Display Fix */
    .element-container { direction: ltr; }
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
    
    # Bullet points formatting
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

tab_feed, tab_strat, tab_tools, tab_map = st.tabs(["🔴 עדכונים שוטפים", "🗂️ תיקי תקיפה", "🛠️ מעבדת חקירות", "🌍 מפת תקיפות"])

# --- TAB 1: LIVE FEED ---
with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    # INCD: Top 4 ALWAYS
    df_incd = pd.read_sql_query("SELECT * FROM intel_reports WHERE source = 'INCD' ORDER BY published_at DESC LIMIT 4", conn)
    # Others: Top 50 recent
    df_rest = pd.read_sql_query("SELECT * FROM intel_reports WHERE source != 'INCD' AND source != 'DeepWeb' AND published_at > datetime('now', '-2 days') ORDER BY published_at DESC LIMIT 50", conn)
    conn.close()
    
    # SORTING LOGIC: Concatenate then sort by date descending
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
    elif "בינוני" in f_sev: df = df[df['severity'].str.contains('Medium', case=False)]
    elif "נמוך" in f_sev: df = df[df['severity'].str.contains('Low|Info', case=False)]

    if df.empty: st.info("לא נמצאו ידיעות התואמות את הסינון.")
    
    for _, row in df.iterrows():
        try:
            dt_obj = row['published_at']
            if dt_obj.tzinfo is None: dt_obj = pytz.utc.localize(dt_obj).astimezone(IL_TZ)
            else: dt_obj = dt_obj.astimezone(IL_TZ)
            date_display = dt_obj.strftime('%d/%m %H:%M')
        except: date_display = str(row['published_at'])
        
        st.markdown(get_feed_card_html(row, date_display), unsafe_allow_html=True)

# --- TAB 2: DOSSIER ---
with tab_strat:
    threats = APTSheetCollector().fetch_threats()
    sel = st.selectbox("בחר קבוצה", [t['name'] for t in threats])
    actor = next(t for t in threats if t['name'] == sel)
    
    st.markdown(f"""
    <div style="background:linear-gradient(180deg, rgba(30, 41, 59, 0.6) 0%, rgba(15, 23, 42, 0.8) 100%); padding:20px; border-radius:10px; border-left:4px solid #f59e0b; direction:ltr;">
        <h2 style="color:white; margin:0;">{actor['name']}</h2>
        <p style="color:#cbd5e1;">{actor['desc']}</p>
        <span style="background:#0f172a; padding:5px 10px; border-radius:5px; font-size:0.8rem; color:#fcd34d;">{actor['origin']}</span>
        <span style="background:#0f172a; padding:5px 10px; border-radius:5px; font-size:0.8rem; color:#fbcfe8;">{actor['target']}</span>
    </div>
    """, unsafe_allow_html=True)
    
    if st.button("🔎 בצע סריקת עומק (Deep Scan)"):
        with st.spinner("מבצע סריקה במקורות Deep Web..."):
            res = DeepWebScanner().scan_actor(actor['name'])
            if res:
                analyzed = asyncio.run(AIBatchProcessor(GROQ_KEY).analyze_batch(res))
                save_reports(res, analyzed)
                st.success(f"נמצאו {len(res)} ממצאים חדשים")
                st.rerun()

# --- TAB 3: TOOLS & LAB ---
with tab_tools:
    st.markdown("#### 🛠️ ארגז כלים")
    toolkit = AnalystToolkit.get_tools()
    
    # NEW TOOLKIT UI - CARDS
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
    ioc_in = st.text_input("הזן אינדיקטור (IP/URL/Hash)")
    
    if st.button("בצע חקירה") and ioc_in:
        itype = identify_ioc_type(ioc_in)
        if itype:
            tl = ThreatLookup(VT_KEY, URLSCAN_KEY, ABUSE_KEY)
            with st.spinner("אוסף מודיעין ממנועים..."):
                vt = tl.query_virustotal(ioc_in, itype)
                us = tl.query_urlscan(ioc_in)
                ab = tl.query_abuseipdb(ioc_in) if itype == 'ip' else None
                
                # --- LAYOUT: HIGH LEVEL METRICS ---
                m1, m2, m3 = st.columns(3)
                
                # VirusTotal Metric
                if vt:
                    mal = vt.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                    m1.metric("VirusTotal", f"{mal} Hits", delta="Malicious" if mal>0 else "Clean", delta_color="inverse")
                else: m1.metric("VirusTotal", "Not Found")
                
                # AbuseIPDB Metric
                if ab:
                    m2.metric("AbuseIPDB", f"{ab.get('abuseConfidenceScore', 0)}%", "Confidence")
                elif itype != 'ip':
                    m2.metric("AbuseIPDB", "N/A", "IP Only")
                else:
                    m2.metric("AbuseIPDB", "Not Found")
                
                # URLScan Metric
                if us:
                    m3.metric("URLScan", "Found", "View Below")
                else:
                    m3.metric("URLScan", "Not Found")
                
                # --- DEEP DIVE TABS ---
                t_ai, t_vt, t_us, t_ab = st.tabs(["🤖 ניתוח AI", "🦠 VirusTotal", "📷 URLScan", "🚫 AbuseIPDB"])
                
                with t_ai:
                    ai_res = asyncio.run(AIBatchProcessor(GROQ_KEY).analyze_single_ioc(ioc_in, itype, {'virustotal': vt, 'urlscan': us}))
                    st.markdown(f'<div style="direction:rtl; text-align:right;">{ai_res}</div>', unsafe_allow_html=True)

                with t_vt:
                    if vt:
                        attr = vt.get('attributes', {})
                        st.json({
                            "Last Analysis": datetime.datetime.fromtimestamp(attr.get('last_analysis_date', 0)).strftime('%Y-%m-%d'),
                            "Reputation": attr.get('reputation'),
                            "Tags": attr.get('tags'),
                            "HTTP Response": attr.get('last_http_response_code'),
                            "Stats": attr.get('last_analysis_stats')
                        })
                    else: st.info("אין נתונים מ-VirusTotal")

                with t_us:
                    if us:
                        task = us.get('task', {})
                        page = us.get('page', {})
                        st.image(task.get('screenshotURL'), caption="צילום מסך מהסריקה")
                        st.write(f"**Redirect:** {page.get('redirectResponse')}")
                        st.write(f"**Country:** {page.get('country')}")
                        st.write(f"**Server:** {page.get('server')}")
                        st.write("**Domains:**")
                        st.write(us.get('lists', {}).get('domains', []))
                    else: st.info("אין נתונים מ-URLScan")

                with t_ab:
                    if ab:
                        st.write(f"**ISP:** {ab.get('isp')}")
                        st.write(f"**Domain:** {ab.get('domain')}")
                        st.write(f"**Usage Type:** {ab.get('usageType')}")
                        st.write(f"**Country:** {ab.get('countryCode')}")
                    else: st.info("רלוונטי ל-IP בלבד / לא נמצאו נתונים")

# --- TAB 4: MAP ---
with tab_map:
    components.iframe("https://threatmap.checkpoint.com/", height=700)

st.markdown("""<div class="footer">SYSTEM ARCHITECT: <b>LIDOR AVRAHAMY</b></div>""", unsafe_allow_html=True)
