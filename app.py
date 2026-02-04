import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import datetime
import pytz
import streamlit.components.v1 as components
from streamlit_autorefresh import st_autorefresh
from utils import *
from dateutil import parser as date_parser

# --- CONFIGURATION ---
st.set_page_config(page_title="CTI War Room", layout="wide", page_icon="🛡️")

# --- HEBREW MAPPING ---
CAT_MAP = {
    "Phishing": "פישינג",
    "Malware": "נוזקות (Malware)",
    "Vulnerabilities": "חולשות (Vulnerabilities)",
    "News": "חדשות סייבר",
    "Research": "מחקר",
    "Other": "אחר"
}

SEV_MAP = {
    "Critical": "קריטי",
    "High": "גבוה",
    "Medium": "בינוני",
    "Low": "נמוך"
}

# --- UI STYLING (FIXED FOR HEBREW UI) ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Assistant:wght@300;400;700&display=swap');
    
    /* Global Font and Direction */
    html, body, [class*="css"] {
        font-family: 'Assistant', sans-serif;
    }
    
    /* Main App Container - Handle RTL for Text Only */
    .stApp {
        direction: rtl; /* Sets base direction to RTL */
        text-align: right;
    }
    
    /* Fix Sidebar Layout issue */
    section[data-testid="stSidebar"] {
        direction: rtl;
        text-align: right;
    }
    
    /* Card Design */
    .report-card { 
        background-color: #ffffff; 
        padding: 15px; 
        border-radius: 10px; 
        border-right: 5px solid #333; 
        margin-bottom: 12px; 
        color: #111 !important; 
        box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        text-align: right;
    }
    
    /* Important for mixed English/Hebrew text */
    .card-title, .card-summary {
        unicode-bidi: embed; 
        text-align: right;
    }

    .card-title { font-weight: 800; font-size: 1.15rem; color: #000 !important; margin: 5px 0; }
    
    /* Tags */
    .tag { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.8rem; font-weight: bold; margin-left: 8px; }
    .tag-critical { background: #ffe6e6; color: #cc0000; border: 1px solid #ffcccc; }
    .tag-incd { background: #000080; color: #ffffff; border: 1px solid #000080; }
    .tag-israel { background: #e6f2ff; color: #004085; }
    .tag-time { background: #f7f7f7; color: #666; border: 1px solid #ddd; }
    
    a { text-decoration: none; color: #0066cc !important; font-weight: bold; }
    a:hover { text-decoration: underline; }
    
    /* Fix Input Fields (IOCs are English) */
    .stTextInput input { 
        direction: ltr !important; 
        text-align: left !important; 
    } 
    
    /* Fix Code Blocks (English) */
    .stCodeBlock, code {
        direction: ltr !important;
        text-align: left !important;
    }

    /* Fix Radio Buttons (Filters) alignment */
    div[role="radiogroup"] {
        direction: rtl;
        text-align: right;
        display: flex;
        flex-direction: row-reverse; /* Ensure they flow correctly */
        justify-content: flex-end;
        gap: 15px;
    }
    
    /* Fix specific Streamlit elements that break in RTL */
    div[data-testid="stMetricValue"] {
        direction: ltr; /* Metrics often contain numbers */
    }
    
</style>
""", unsafe_allow_html=True)

# --- INITIALIZATION ---
init_db() 
REFRESH_MINUTES = 15
st_autorefresh(interval=REFRESH_MINUTES * 60 * 1000, key="auto_refresh")

GROQ_KEY = st.secrets.get("groq_key", "")
VT_KEY = st.secrets.get("vt_key", "")
URLSCAN_KEY = st.secrets.get("urlscan_key", "")
ABUSE_KEY = st.secrets.get("abuseipdb_key", "")

IL_TZ = pytz.timezone('Asia/Jerusalem')

# --- SIDEBAR ---
with st.sidebar:
    st.header("⚙️ סטטוס מערכת")
    ok, msg = ConnectionManager.check_groq(GROQ_KEY)
    st.markdown(f"**Groq AI**: {'✅' if ok else '❌'} ({msg})")
    
    st.divider()
    
    if st.button("🚀 עדכון מודיעין יזום", type="primary"):
        with st.status("מושך מידע חדש...", expanded=True):
            async def run_update():
                col, proc = CTICollector(), AIBatchProcessor(GROQ_KEY)
                st.write("מתחבר למקורות (RSS, Telegram)...")
                raw = await col.get_all_data()
                if not raw: 
                    st.warning("לא נמצאו ידיעות חדשות.")
                    return 0
                st.write(f"מנתח {len(raw)} ידיעות באמצעות AI...")
                analyzed = await proc.analyze_batch(raw)
                return save_reports(raw, analyzed)
            count = asyncio.run(run_update())
            st.success(f"נוספו {count} ידיעות חדשות.")
            st.rerun()
    
    st.info("המערכת מתרעננת אוטומטית כל 15 דקות.")

# --- MAIN TABS ---
# Tabs names in Hebrew
tab_feed, tab_tools, tab_strat, tab_map = st.tabs(["🔴 עדכונים חיים", "🛠️ חקירות SOC", "🧠 מודיעין אסטרטגי", "🌍 מפת איומים"])

# --- TAB 1: LIVE FEED ---
with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    
    # 1. Fetch Logic
    df_incd = pd.read_sql_query("SELECT * FROM intel_reports WHERE source = 'INCD' ORDER BY published_at DESC", conn)
    df_others = pd.read_sql_query("SELECT * FROM intel_reports WHERE source != 'INCD' AND published_at > datetime('now', '-2 days') ORDER BY published_at DESC", conn)
    conn.close()
    
    now_ts = pd.Timestamp.now(tz=IL_TZ)
    
    if not df_incd.empty:
        df_incd['dt'] = pd.to_datetime(df_incd['published_at'], utc=True).dt.tz_convert(IL_TZ)
        cond_time = (now_ts - df_incd['dt']).dt.total_seconds() < (96 * 3600)
        df_incd_filtered = df_incd[cond_time | (df_incd.index < 4)].copy()
    else:
        df_incd_filtered = df_incd

    if not df_others.empty:
         df_others['dt'] = pd.to_datetime(df_others['published_at'], utc=True).dt.tz_convert(IL_TZ)
    
    df_final = pd.concat([df_incd_filtered, df_others]).sort_values(by='published_at', ascending=False).drop_duplicates(subset=['url'])
    
    # 2. FILTERING SYSTEM
    if df_final.empty:
        st.info("אין התראות פעילות ב-48 השעות האחרונות.")
    else:
        # Hebrew mapping for filters
        df_final['display_cat'] = df_final['category'].map(CAT_MAP).fillna(df_final['category'])
        cat_counts = df_final['display_cat'].value_counts()
        
        radio_labels = []
        mapping_back = {} 
        
        total_count = len(df_final)
        label_all = f"כל הידיעות ({total_count})"
        radio_labels.append(label_all)
        mapping_back[label_all] = "ALL"
        
        for cat in cat_counts.index:
            count = cat_counts[cat]
            label = f"{cat} ({count})"
            radio_labels.append(label)
            mapping_back[label] = cat
            
        st.write("📂 **סינון לפי נושא:**")
        # Ensure horizontal layout
        selected_label = st.radio("Select Category", radio_labels, horizontal=True, label_visibility="collapsed")
        
        selected_cat_clean = mapping_back.get(selected_label, "ALL")
        
        if selected_cat_clean != "ALL":
            df_display = df_final[df_final['display_cat'] == selected_cat_clean]
        else:
            df_display = df_final

        st.divider()

        # 3. RENDER CARDS
        for _, row in df_display.iterrows():
            pub_date = row['dt']
            
            sev_heb = SEV_MAP.get(row['severity'], row['severity'])
            sev_class = "tag-critical" if "Critical" in row['severity'] else ""
            source_tag = "tag-incd" if row['source'] == "INCD" else "tag-time"
            cat_display = row['display_cat']
            
            st.markdown(f"""
            <div class="report-card">
                <span class="tag {source_tag}">{row['source']}</span>
                <span class="tag tag-time">{pub_date.strftime('%d/%m %H:%M')}</span>
                <span class="tag {sev_class}">{sev_heb}</span>
                <span class="tag tag-israel">{cat_display}</span>
                <div class="card-title">{row['title']}</div>
                <div class="card-summary">{row['summary']}</div>
                <div style="font-size: 0.8rem; color: #666; margin-top:5px;">
                    <a href="{row['url']}" target="_blank">🔗 למעבר לדיווח המלא</a>
                </div>
            </div>
            """, unsafe_allow_html=True)

# --- TAB 2: SOC TOOLBOX ---
with tab_tools:
    st.subheader("🛠️ חדר חקירות - בדיקת מזהים (IOC)")
    
    c_input, c_btn = st.columns([4, 1])
    with c_input:
        ioc_input = st.text_input("הזן מזהה לחקירה", placeholder="לדוגמה: 1.2.3.4, evil.com").strip()
    with c_btn:
        st.write("") 
        st.write("") 
        btn_scan = st.button("חקור עכשיו 🕵️")

    if btn_scan and ioc_input:
        ioc_type = identify_ioc_type(ioc_input)
        
        if not ioc_type:
            st.error("❌ קלט לא תקין! יש להזין IP, דומיין או Hash תקינים.")
        else:
            st.success(f"זוהה סוג מזהה: {ioc_type.upper()}")
            tl = ThreatLookup(VT_KEY, URLSCAN_KEY, ABUSE_KEY)
            results = {}
            
            with st.status("סורק במאגרי מידע חיצוניים...", expanded=True):
                st.write("פונה ל-VirusTotal...")
                vt = tl.query_virustotal(ioc_input, ioc_type)
                results['virustotal'] = vt if vt else "No Data"
                
                if ioc_type == "domain":
                    st.write("פונה ל-URLScan.io...")
                    us = tl.query_urlscan(ioc_input)
                    results['urlscan'] = us if us else "No Data"
                
                if ioc_type == "ip":
                    st.write("פונה ל-AbuseIPDB...")
                    ab = tl.query_abuseipdb(ioc_input)
                    results['abuseipdb'] = ab if ab else "No Data"
                    
            # Raw Data Cards
            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown("### 🦠 VirusTotal")
                if isinstance(results.get('virustotal'), dict):
                    stats = results['virustotal'].get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    # Translate stats key for display if needed or keep english for tech clarity
                    color = "red" if malicious > 0 else "green"
                    st.markdown(f":{color}[**זיהויים זדוניים: {malicious}**]")
                    st.json(stats)
                else: st.write("אין מידע")
                
            with c2:
                st.markdown("### 🌐 URLScan")
                if ioc_type == 'domain' and isinstance(results.get('urlscan'), dict):
                    verdict = results['urlscan'].get('verdict', {}).get('overall', 'Unknown')
                    # Simple translation map for UI
                    v_map = {"malicious": "זדוני", "clean": "נקי", "no_classification": "ללא סיווג"}
                    st.write(f"פסיקה: {v_map.get(verdict, verdict)}")
                    if results['urlscan'].get('screenshot'): st.image(results['urlscan']['screenshot'])
                else: st.write("לא רלוונטי")
                
            with c3:
                st.markdown("### 🛑 AbuseIPDB")
                if ioc_type == 'ip' and isinstance(results.get('abuseipdb'), dict):
                    score = results['abuseipdb'].get('abuseConfidenceScore', 0)
                    st.metric("ציון זדוניות", f"{score}%")
                    st.write(f"ספק (ISP): {results['abuseipdb'].get('isp')}")
                else: st.write("לא רלוונטי")

            st.divider()
            st.subheader("🤖 ניתוח אנליסט בכיר (AI Mentor)")
            with st.spinner("מגבש חוות דעת מקצועית בעברית..."):
                proc = AIBatchProcessor(GROQ_KEY)
                report = asyncio.run(proc.analyze_single_ioc(ioc_input, ioc_type, results))
                st.markdown(report)

# --- TAB 3: STRATEGIC INTEL ---
with tab_strat:
    st.subheader("🧠 מודיעין אסטרטגי - קמפיינים פעילים")
    st.markdown("מיקוד: **איראן והמזרח התיכון** | יעד: **ארגונים ישראליים**")
    
    threats = APTSheetCollector().fetch_threats()
    
    for actor in threats:
        with st.expander(f"👹 {actor['name']} ({actor['origin']}) - {actor['type']}"):
            col_desc, col_acts = st.columns([2, 1])
            with col_desc:
                st.markdown(f"**תיאור:** {actor['desc']}")
                st.markdown(f"**כלים:** `{actor['tools']}`")
                st.markdown(f"**MITRE:** `{actor['mitre']}`")
            with col_acts:
                if st.button(f"🏹 צור שאילתות ציד ({actor['name']})"):
                    proc = AIBatchProcessor(GROQ_KEY)
                    with st.spinner("מייצר שאילתות XQL ו-YARA (הסברים בעברית)..."):
                        res = asyncio.run(proc.generate_hunting_queries(actor))
                        st.markdown(res)
    
    st.divider()
    st.subheader("🔥 מזהים חמים (Trending IOCs)")
    st.info("אינדיקטורים אחרונים שזוהו בקמפיינים נגד ישראל (סימולציה)")
    
    st.markdown("""
    | אינדיקטור | סוג | שחקן | רמת ביטחון |
    |-----------|------|-------|------------|
    | `185.200.118.55` | IP | MuddyWater | גבוהה |
    | `update-win-srv.com` | Domain | OilRig | בינונית |
    | `0a8b9c...2d1` | SHA256 | Agonizing Serpens | קריטית |
    """)

# --- TAB 4: MAP ---
with tab_map:
    components.iframe("https://threatmap.checkpoint.com/", height=600)
