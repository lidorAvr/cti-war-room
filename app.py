import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import base64
import re
import json
import streamlit.components.v1 as components
from streamlit_autorefresh import st_autorefresh
from utils import (init_db, CTICollector, AIBatchProcessor, save_reports, 
                   AbuseIPDBChecker, APTSheetCollector, MitreCollector, 
                   IOCExtractor, ThreatLookup, DB_NAME, get_ioc_type, ConnectionManager)
from dateutil import parser

st.set_page_config(page_title="SOC War Room", layout="wide", page_icon="🛡️")

# --- CSS Styling ---
st.markdown("""
<style>
    .report-card { background-color: #1E1E1E; padding: 15px; border-radius: 8px; border: 1px solid #333; margin-bottom: 10px; }
    .tag { padding: 2px 8px; border-radius: 4px; font-weight: bold; font-size: 0.75rem; margin-right: 5px; }
    .tag-critical { background-color: #721c24; color: #f8d7da; border: 1px solid #f5c6cb; }
    .tag-high { background-color: #856404; color: #fff3cd; }
    .tag-israel { background-color: #004085; color: #cce5ff; border: 1px solid #b8daff; }
    .tag-medium { background-color: #0c5460; color: #d1ecf1; }
    .tool-box { background-color: #252526; padding: 20px; border-radius: 10px; border-left: 5px solid #007acc; }
    iframe { border-radius: 10px; border: 1px solid #333; }
    
    /* Status Indicators */
    .status-ok { color: #4CAF50; font-weight: bold; }
    .status-err { color: #F44336; font-weight: bold; }
</style>
""", unsafe_allow_html=True)

st_autorefresh(interval=15 * 60 * 1000, key="auto_refresh")
init_db()

if 'filter_type' not in st.session_state: st.session_state.filter_type = 'All'

st.title("🛡️ SOC War Room")
st.caption("Integrated Threat Intelligence, Investigation Tools & Global Monitoring")

# --- SECRET LOADING HELPER ---
def load_secret(key_name):
    # מנסה לטעון מ-secrets.toml, אם לא קיים מחזיר מחרוזת ריקה
    try:
        return st.secrets.get(key_name, "")
    except FileNotFoundError:
        return ""

# --- Sidebar Controls ---
with st.sidebar:
    st.header("⚙️ System Status")
    
    # טעינת מפתחות אוטומטית
    gemini_key = load_secret("gemini_key")
    abuse_key = load_secret("abuseipdb_key")
    abuse_ch_key = load_secret("abuse_ch_key")
    vt_key = load_secret("vt_key")
    urlscan_key = load_secret("urlscan_key")
    cyscan_key = load_secret("cyscan_key")
    
    # --- בדיקת חיבורים (מבוצעת בלחיצה כדי לחסוך קריאות API) ---
    if st.button("🔄 Test API Connections"):
        with st.spinner("Checking endpoints..."):
            st.markdown("---")
            
            # Gemini Check
            ok, msg = ConnectionManager.check_gemini(gemini_key)
            icon = "✅" if ok else "❌"
            st.markdown(f"{icon} **Gemini AI**: {msg}")
            
            # AbuseIPDB Check
            ok, msg = ConnectionManager.check_abuseipdb(abuse_key)
            icon = "✅" if ok else "❌"
            st.markdown(f"{icon} **AbuseIPDB**: {msg}")
            
            # Abuse.ch Check
            ok, msg = ConnectionManager.check_abusech(abuse_ch_key)
            icon = "✅" if ok else "⚠️" # צהוב כי זה לא קריטי אם נכשל
            st.markdown(f"{icon} **Abuse.ch**: {msg}")

            # VirusTotal Check
            ok, msg = ConnectionManager.check_virustotal(vt_key)
            icon = "✅" if ok else "⚠️"
            st.markdown(f"{icon} **VirusTotal**: {msg}")

            # urlscan.io Check
            ok, msg = ConnectionManager.check_urlscan(urlscan_key)
            icon = "✅" if ok else "⚠️"
            st.markdown(f"{icon} **urlscan.io**: {msg}")
            
            st.markdown("---")
    
    st.info(f"Loaded Keys: {sum([1 for k in [gemini_key, abuse_key, abuse_ch_key, vt_key, urlscan_key] if k])}/5")

    st.divider()
    
    if st.button("🚀 Run Global Intel Scan", disabled=not gemini_key):
        with st.spinner("Scanning RSS Feeds & CISA..."):
            async def scan():
                col, proc = CTICollector(), AIBatchProcessor(gemini_key)
                raw = await col.get_all_data()
                analyzed = await proc.analyze_batch(raw)
                return save_reports(raw, analyzed)
            c = asyncio.run(scan())
            st.success(f"Scan complete. {c} new reports.")
            st.rerun()

# --- MAIN TABS ---
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
        st.info("No reports match current filters.")
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
    st.markdown("<div class='tool-box'><h3>🛠️ Analyst Investigation Suite</h3><p>Active tools for IOC analysis. Enter an IP, Domain, Hash, or URL.</p></div>", unsafe_allow_html=True)
    
    t1, t2, t3 = st.tabs(["🔍 Universal Lookup", "📝 IOC Extractor", "🔓 Decoders"])
    
    with t1:
        st.caption("Auto-checks: AbuseIPDB, ThreatFox, URLhaus, VirusTotal, urlscan.io")
        col1, col2 = st.columns([3, 1])
        ioc_input = col1.text_input("Enter Indicator", placeholder="e.g. 1.2.3.4, evil.com, or file hash")
        
        # Session State for AI Report
        if 'analysis_results' not in st.session_state: st.session_state.analysis_results = None
        if 'ioc_target' not in st.session_state: st.session_state.ioc_target = None

        if col2.button("Investigate"):
            if not ioc_input: st.warning("Enter an IOC")
            else:
                st.session_state.ioc_target = ioc_input
                st.divider()
                ioc_type = get_ioc_type(ioc_input)
                st.markdown(f"**Detected Type:** `{ioc_type.upper()}`")
                
                # Data Aggregation Object
                intel_data = {"ioc": ioc_input, "type": ioc_type, "timestamp": str(pd.Timestamp.now())}

                # 1. AbuseIPDB
                if ioc_type == "ip" and abuse_key:
                    res = AbuseIPDBChecker(abuse_key).check_ip(ioc_input)
                    intel_data['abuseipdb'] = res
                    if "success" in res:
                        d = res['data']
                        score = d['abuseConfidenceScore']
                        color = "red" if score > 50 else "green"
                        st.markdown(f"#### 🌐 AbuseIPDB: :{color}[{score}% Malicious]")
                        st.write(f"ISP: {d['isp']} | {d['countryCode']}")
                    else: st.warning(f"AbuseIPDB: {res.get('error')}")
                
                # 2. ThreatFox & URLhaus & VirusTotal & urlscan
                tl = ThreatLookup(abuse_ch_key, vt_key, urlscan_key, cyscan_key)
                
                # ThreatFox
                tf = tl.query_threatfox(ioc_input)
                intel_data['threatfox'] = tf
                if tf['status'] == 'found':
                    st.error(f"🚨 ThreatFox: Found {len(tf['data'])} records")
                    st.json(tf['data'][0])
                
                # URLhaus
                uh = tl.query_urlhaus(ioc_input)
                intel_data['urlhaus'] = uh
                if uh['status'] == 'found':
                    st.error(f"🚨 URLhaus: Found")
                    st.write(uh['data'])

                # VirusTotal
                vt = tl.query_virustotal(ioc_input)
                intel_data['virustotal'] = vt
                if vt['status'] == 'found':
                    stats = vt['stats']
                    malicious = stats.get('malicious', 0)
                    total = sum(stats.values())
                    color = "red" if malicious > 0 else "green"
                    st.markdown(f"#### 🦠 VirusTotal: :{color}[{malicious}/{total} Malicious]")
                    st.bar_chart(stats)
                elif vt['status'] == 'not_found': st.success("VirusTotal: Clean / Not Found")
                
                # urlscan.io
                us = tl.query_urlscan(ioc_input)
                intel_data['urlscan'] = us
                if us['status'] == 'found':
                    st.markdown("#### 📷 urlscan.io Result")
                    c1, c2 = st.columns([1,2])
                    with c1:
                         if us.get('screenshot'): st.image(us['screenshot'], caption="Latest Scan")
                    with c2:
                         st.write(f"**Verdict:** {us.get('verdict', {}).get('overall', 'Unknown')}")
                         st.write(f"**Page:** {us.get('page', {}).get('url', 'N/A')}")
                
                # CyScan (Direct Link)
                cs = tl.query_cyscan(ioc_input)
                intel_data['cyscan'] = cs
                st.markdown(f"#### 🔎 CyScan")
                st.markdown(f"[Open Report in CyScan]({cs['link']})")
                
                st.session_state.analysis_results = intel_data
        
        # --- AI Analyst Button ---
        if st.session_state.analysis_results and gemini_key:
            st.divider()
            if st.button("✨ Ask AI Analyst to Summarize"):
                with st.spinner("AI Analyst is reviewing the evidence..."):
                    proc = AIBatchProcessor(gemini_key)
                    report = asyncio.run(proc.analyze_single_ioc(st.session_state.ioc_target, st.session_state.analysis_results))
                    st.markdown("### 🤖 AI Analyst Report")
                    st.markdown(report)

    with t2:
        st.subheader("Extract IOCs from Text")
        raw_text = st.text_area("Paste text here:", height=150)
        if st.button("Extract"):
            extracted = IOCExtractor().extract(raw_text)
            st.json(extracted)

    with t3:
        st.subheader("Quick Decoders")
        d_in = st.text_input("Encoded String")
        if d_in:
            try: st.code(base64.b64decode(d_in).decode(), language="text")
            except: st.error("Invalid Base64")

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
