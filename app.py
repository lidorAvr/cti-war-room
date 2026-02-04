import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import base64
import json
import streamlit.components.v1 as components # הוספתי את הייבוא שהיה חסר!
from streamlit_autorefresh import st_autorefresh
from utils import * # --- CONFIGURATION (מופרד לשורה חדשה ותקינה) ---
st.set_page_config(page_title="SOC War Room", layout="wide", page_icon="🛡️")

# --- STYLING ---
st.markdown("""
<style>
    .report-card { background-color: #1E1E1E; padding: 15px; border-radius: 8px; border: 1px solid #333; margin-bottom: 10px; }
    .tag { padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; margin-right: 5px; }
    .tag-critical { background-color: #721c24; color: #f8d7da; }
    .tag-high { background-color: #856404; color: #fff3cd; }
    .tag-israel { background-color: #004085; color: #cce5ff; }
    .tag-medium { background-color: #0c5460; color: #d1ecf1; }
    .tool-box { background-color: #252526; padding: 20px; border-radius: 10px; border-left: 5px solid #007acc; }
    iframe { border-radius: 10px; border: 1px solid #333; }
    .status-ok { color: #4CAF50; font-weight: bold; }
    .status-err { color: #F44336; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

st_autorefresh(interval=15 * 60 * 1000, key="auto_refresh")
init_db()

if 'filter_type' not in st.session_state: st.session_state.filter_type = 'All'

st.title("🛡️ SOC War Room")
st.caption("Integrated Threat Intelligence, Investigation Tools & Global Monitoring")

# --- SIDEBAR: KEY CONFIGURATION ---
with st.sidebar:
    st.header("🔧 API Configuration")
    
    # ניסיון לטעון מ-Secrets
    try: 
        secret_key = st.secrets["gemini_key"]
    except: 
        secret_key = ""
    
    # תיבת טקסט למפתח
    user_key = st.text_input("Gemini API Key:", value=secret_key, type="password")
    
    # המפתח בפועל לשימוש
    gemini_key = user_key

    if st.button("🧪 Test Connection"):
        if gemini_key:
            with st.spinner("Connecting to Google..."):
                ok, msg = ConnectionManager.check_gemini(gemini_key)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)
        else:
            st.warning("Please enter a key first.")
            
    st.divider()
    
    # בדיקות נוספות
    with st.expander("System Checks"):
        try: secret_abuse = st.secrets["abuseipdb_key"]
        except: secret_abuse = ""
        if st.button("Check Integrations"):
             ok, msg = ConnectionManager.check_abuseipdb(secret_abuse)
             st.write(f"AbuseIPDB: {msg}")

    
    if st.button("🚀 Run Global Intel Scan", disabled=not gemini_key):
        with st.spinner("Scanning RSS Feeds & CISA..."):
            async def scan():
                # אתחול האובייקטים
                col = CTICollector()
                # מעבירים את המפתח ל-Processor
                proc = AIBatchProcessor(gemini_key)
                
                raw = await col.get_all_data()
                analyzed = await proc.analyze_batch(raw)
                return save_reports(raw, analyzed)
            
            c = asyncio.run(scan())
            st.success(f"Scan Logic Finished. Items processed: {c}")
            st.rerun()

# --- TABS ---
tab_feed, tab_tools, tab_landscape, tab_map = st.tabs(["🔴 Live Feed", "🛠️ SOC Toolbox", "🌍 Threat Landscape", "🗺️ Live Attack Map"])

with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM intel_reports ORDER BY published_at DESC", conn)
    conn.close()
    
    c1, c2, c3, c4 = st.columns(4)
    if c1.button(f"🚨 Critical ({len(df[df['severity']=='Critical'])})", use_container_width=True): st.session_state.filter_type = 'Critical'
    if c2.button(f"🇮🇱 Israel ({len(df[df['category']=='Israel Focus'])})", use_container_width=True): st.session_state.filter_type = 'Israel'
    if c3.button(f"🦠 Malware", use_container_width=True): st.session_state.filter_type = 'Malware'
    if c4.button("🌐 All Reports", use_container_width=True): st.session_state.filter_type = 'All'

    view_df = df
    if st.session_state.filter_type == 'Critical': view_df = df[df['severity'] == 'Critical']
    elif st.session_state.filter_type == 'Israel': view_df = df[df['category'] == 'Israel Focus']
    elif st.session_state.filter_type == 'Malware': view_df = df[df['category'] == 'Malware']

    if view_df.empty:
        st.info("No reports yet. Click 'Run Global Intel Scan' in the sidebar.")
    else:
        for _, row in view_df.iterrows():
            sev_class = "tag-critical" if row['severity']=='Critical' else ("tag-high" if row['severity']=='High' else "tag-medium")
            cat_class = "tag-israel" if row['category']=='Israel Focus' else "tag-medium"
            st.markdown(f"""
            <div class="report-card">
                <div style="display:flex; justify-content:space-between; margin-bottom:5px;">
                    <div><span class="tag {sev_class}">{row['severity']}</span><span class="tag {cat_class}">{row['category']}</span></div>
                    <small style="color:#888">{row['source']}</small>
                </div>
                <h4 style="margin:5px 0">{row['title']}</h4>
                <p style="color:#ccc; font-size:0.95rem;">{row['summary']}</p>
                <div style="display:flex; justify-content:space-between; font-size:0.85rem;">
                    <span style="color:#aaa"><strong>Impact:</strong> {row['impact']}</span>
                    <a href="{row['url']}" target="_blank" style="color:#4da6ff;">Read More ↗</a>
                </div>
            </div>""", unsafe_allow_html=True)

with tab_tools:
    st.markdown("<div class='tool-box'><h3>🛠️ Analyst Investigation Suite</h3><p>Active tools for IOC analysis.</p></div>", unsafe_allow_html=True)
    
    t1, t2 = st.tabs(["🔍 Universal Lookup", "📝 IOC Extractor"])
    
    with t1:
        ioc_input = st.text_input("Enter Indicator (IP/Domain/Hash)", placeholder="e.g. 1.1.1.1")
        if st.button("Investigate"):
            if gemini_key:
                # 1. Get Tools Data
                try: secret_vt = st.secrets["vt_key"]
                except: secret_vt = ""
                
                st.info("Querying Threat Intelligence Sources...")
                tl = ThreatLookup(vt_key=secret_vt)
                vt_res = tl.query_virustotal(ioc_input)
                
                # 2. AI Analysis
                st.info("Asking AI Analyst...")
                proc = AIBatchProcessor(gemini_key)
                
                # Combine data for AI
                context = {"ioc": ioc_input, "virustotal": vt_res}
                res = asyncio.run(proc.analyze_single_ioc(ioc_input, context))
                
                st.markdown("### 🤖 AI Analyst Report")
                st.markdown(res)
                
                if vt_res.get('status') == 'found':
                    st.json(vt_res)
            else:
                st.error("Enter API Key first.")

    with t2:
        raw_text = st.text_area("Paste text to extract IOCs:", height=150)
        if st.button("Extract"):
            extracted = IOCExtractor().extract(raw_text)
            st.json(extracted)

with tab_landscape:
    mitre = MitreCollector().get_latest_updates()
    if mitre:
        st.info(f"📢 **MITRE ATT&CK Update:** [{mitre['title']}]({mitre['url']})")

    st.subheader("Global APT Groups Operations")
    col1, col2 = st.columns([1, 4])
    region = col1.radio("Select Theater", ["Israel", "Russia", "China", "Iran"])
    if col1.button("Load Intel"):
        with st.spinner(f"Querying {region} Database..."):
            df_apt = APTSheetCollector().fetch_threats(region)
            if not df_apt.empty:
                st.dataframe(df_apt, use_container_width=True)
            else:
                st.warning("No data found.")

with tab_map:
    st.subheader("🌐 Check Point ThreatCloud Map")
    components.iframe("https://threatmap.checkpoint.com/", height=800, scrolling=False)
