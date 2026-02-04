import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import base64
from streamlit_autorefresh import st_autorefresh
from utils import (init_db, CTICollector, AIBatchProcessor, save_reports, 
                   AbuseIPDBChecker, APTSheetCollector, MitreCollector, 
                   IOCExtractor, ThreatLookup, DB_NAME)
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
</style>
""", unsafe_allow_html=True)

st_autorefresh(interval=15 * 60 * 1000, key="auto_refresh")
init_db()

if 'filter_type' not in st.session_state: st.session_state.filter_type = 'All'

# --- Header ---
st.title("🛡️ SOC War Room")
st.caption("Integrated Threat Intelligence, Investigation Tools & Global Monitoring")

# --- Sidebar Controls ---
with st.sidebar:
    st.header("⚙️ Config")
    gemini_key = st.text_input("Gemini API Key", type="password").strip() or None
    abuse_key = st.text_input("AbuseIPDB Key", type="password").strip() or None
    
    st.divider()
    if st.button("🚀 Force Global Scan", disabled=not gemini_key):
        with st.spinner("Scanning Sources..."):
            async def scan():
                col, proc = CTICollector(), AIBatchProcessor(gemini_key)
                raw = await col.get_all_data()
                analyzed = await proc.analyze_batch(raw)
                return save_reports(raw, analyzed)
            c = asyncio.run(scan())
            st.success(f"Scan complete. {c} new reports.")
            st.rerun()

# --- MAIN TABS ---
tab_feed, tab_tools, tab_landscape = st.tabs(["🔴 Live Feed", "🛠️ SOC Toolbox", "🌍 Threat Landscape"])

# --- TAB 1: LIVE FEED ---
with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    df = pd.read_sql_query("SELECT * FROM intel_reports ORDER BY published_at DESC", conn)
    conn.close()
    
    # Filter Bar
    c1, c2, c3, c4 = st.columns(4)
    if c1.button(f"🚨 Critical ({len(df[df['severity']=='Critical'])})", use_container_width=True): st.session_state.filter_type = 'Critical'
    if c2.button(f"🇮🇱 Israel ({len(df[df['category']=='Israel Focus'])})", use_container_width=True): st.session_state.filter_type = 'Israel'
    if c3.button(f"🦠 Malware", use_container_width=True): st.session_state.filter_type = 'Malware'
    if c4.button("🌐 All Reports", use_container_width=True): st.session_state.filter_type = 'All'

    # Filter Logic
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

# --- TAB 2: SOC TOOLBOX ---
with tab_tools:
    st.markdown("<div class='tool-box'><h3>🛠️ Analyst Investigation Suite</h3><p>Active tools for IOC analysis and extraction.</p></div>", unsafe_allow_html=True)
    
    t1, t2, t3 = st.tabs(["🔍 Universal Lookup", "📝 IOC Extractor", "🔓 Decoders"])
    
    with t1:
        st.subheader("Check IP / Hash / URL")
        col1, col2 = st.columns([3, 1])
        ioc_input = col1.text_input("Enter Indicator (IP, Domain, MD5, SHA256)")
        
        if col2.button("Investigate"):
            if not ioc_input: st.warning("Enter an IOC")
            else:
                st.divider()
                # 1. AbuseIPDB
                if abuse_key:
                    res = AbuseIPDBChecker(abuse_key).check_ip(ioc_input)
                    if "success" in res:
                        d = res['data']
                        st.success(f"✅ AbuseIPDB: {d['abuseConfidenceScore']}% Malicious | ISP: {d['isp']} | {d['countryCode']}")
                    else: st.warning("AbuseIPDB: Not an IP or Key missing")
                
                # 2. ThreatFox & URLhaus (Abuse.ch)
                tl = ThreatLookup()
                tf_res = tl.query_threatfox(ioc_input)
                if tf_res:
                    st.error(f"🚨 ThreatFox Found: {len(tf_res)} records!")
                    st.json(tf_res[0])
                else: st.info("ThreatFox: No Match")
                
                uh_res = tl.query_urlhaus(ioc_input)
                if uh_res and uh_res['query_status'] == 'ok':
                    st.error(f"🚨 URLhaus Found: {uh_res['url_status']}")
                    st.write(f"Tags: {uh_res['tags']}")
                else: st.info("URLhaus: No Match")

    with t2:
        st.subheader("Extract IOCs from Text")
        raw_text = st.text_area("Paste report text, email headers, or logs here:", height=150)
        if st.button("Extract Artifacts"):
            extracted = IOCExtractor().extract(raw_text)
            c1, c2, c3 = st.columns(3)
            c1.write("### 🌐 IPs"); c1.write(extracted['IPs'])
            c2.write("### 🔗 Domains"); c2.write(extracted['Domains'])
            c3.write("### #️⃣ Hashes"); c3.write(extracted['Hashes'])

    with t3:
        st.subheader("Quick Decoders")
        d_in = st.text_input("Encoded String")
        if d_in:
            try: st.code(base64.b64decode(d_in).decode(), language="text", line_numbers=False)
            except: st.error("Invalid Base64")

# --- TAB 3: THREAT LANDSCAPE ---
with tab_landscape:
    # MITRE Update
    mitre = MitreCollector().get_latest_updates()
    if mitre:
        st.info(f"📢 **MITRE ATT&CK Update:** [{mitre['title']}]({mitre['url']})")

    st.subheader("Global APT Groups Operations (Google Sheets)")
    
    col1, col2 = st.columns([1, 4])
    region = col1.radio("Select Theater", ["Israel", "Russia", "China", "Iran"])
    
    if col1.button("Load Intel"):
        with st.spinner(f"Querying {region} Database..."):
            df_apt = APTSheetCollector().fetch_threats(region)
            if not df_apt.empty:
                st.dataframe(df_apt, use_container_width=True)
            else:
                st.warning("No data found.")
