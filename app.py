import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import base64
import json
from streamlit_autorefresh import st_autorefresh
from utils import * from dateutil import parser

# --- CONFIGURATION ---
st.set_page_config(page_title="SOC War Room", layout="wide", page_icon="🛡️")

# --- CUSTOM CSS (UI IMPROVEMENTS) ---
st.markdown("""
<style>
    /* Global Font Size */
    html, body, [class*="css"] {
        font-family: 'Segoe UI', sans-serif;
        font-size: 18px !important;
    }
    
    /* Report Cards */
    .report-card {
        background-color: #262730;
        padding: 20px;
        border-radius: 12px;
        border: 1px solid #444;
        margin-bottom: 15px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        transition: transform 0.2s;
    }
    .report-card:hover {
        transform: translateY(-2px);
        border-color: #666;
    }
    
    /* Tags */
    .tag {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem !important;
        margin-right: 8px;
        letter-spacing: 0.5px;
    }
    .tag-time { background-color: #333; color: #bbb; border: 1px solid #555; }
    .tag-critical { background-color: #5a1a1a; color: #ffcccc; border: 1px solid #800000; }
    .tag-high { background-color: #5a4a1a; color: #ffffcc; border: 1px solid #806000; }
    .tag-israel { background-color: #1a3a5a; color: #cce5ff; border: 1px solid #004080; }
    .tag-medium { background-color: #1a5a5a; color: #ccffff; border: 1px solid #006060; }
    
    /* Headers */
    h4 { margin-top: 10px; margin-bottom: 10px; color: #fff; font-weight: 600; }
    p { color: #ddd; line-height: 1.6; }
    a { text-decoration: none; color: #4da6ff; font-weight: bold; }
    
    /* Tool Box */
    .tool-box {
        background-color: #1e1e1e;
        padding: 25px;
        border-radius: 15px;
        border-left: 6px solid #007acc;
        margin-bottom: 20px;
    }
</style>
""", unsafe_allow_html=True)

# --- AUTO REFRESH (15 Minutes) ---
st_autorefresh(interval=15 * 60 * 1000, key="auto_refresh")
init_db()

if 'filter_type' not in st.session_state: st.session_state.filter_type = 'All'
if 'ioc_data' not in st.session_state: st.session_state.ioc_data = None
if 'current_ioc' not in st.session_state: st.session_state.current_ioc = ""

st.title("🛡️ SOC War Room")

# --- SIDEBAR ---
with st.sidebar:
    st.header("🔧 API Configuration")
    
    try: secret_key = st.secrets["gemini_key"]
    except: secret_key = ""
    user_key = st.text_input("Gemini API Key:", value=secret_key, type="password")
    gemini_key = user_key

    if st.button("🧪 Test Connection"):
        if gemini_key:
            with st.spinner("Connecting..."):
                ok, msg = ConnectionManager.check_gemini(gemini_key)
                if ok: st.success(msg)
                else: st.error(msg)
    
    st.divider()
    
    if st.button("🚀 Run Global Scan Now"):
        with st.spinner("Scanning Feeds & Deleting Old Items..."):
            async def scan():
                col = CTICollector()
                proc = AIBatchProcessor(gemini_key)
                raw = await col.get_all_data()
                analyzed = await proc.analyze_batch(raw)
                return save_reports(raw, analyzed)
            
            c = asyncio.run(scan())
            st.success(f"Updated. {c} new items.")
            st.rerun()

# --- TABS ---
tab_feed, tab_tools = st.tabs(["🔴 Live Feed", "🛠️ SOC Toolbox"])

with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    # שליפת המידע ממוין לפי תאריך פרסום
    df = pd.read_sql_query("SELECT * FROM intel_reports ORDER BY published_at DESC", conn)
    conn.close()
    
    # פילטרים
    c1, c2, c3, c4 = st.columns(4)
    if c1.button(f"🚨 Critical ({len(df[df['severity']=='Critical'])})", use_container_width=True): st.session_state.filter_type = 'Critical'
    if c2.button(f"🇮🇱 Israel Focus ({len(df[df['category']=='Israel Focus'])})", use_container_width=True): st.session_state.filter_type = 'Israel'
    if c3.button("All Reports", use_container_width=True): st.session_state.filter_type = 'All'

    view_df = df
    if st.session_state.filter_type == 'Critical': view_df = df[df['severity'] == 'Critical']
    elif st.session_state.filter_type == 'Israel': view_df = df[df['category'] == 'Israel Focus']

    if view_df.empty:
        st.info("No reports available. Wait for auto-refresh or click 'Run Global Scan' in the sidebar.")
    else:
        for _, row in view_df.iterrows():
            # עיצוב התאריך לתצוגה יפה (DD/MM HH:MM)
            try:
                dt_obj = parser.parse(row['published_at'])
                display_date = dt_obj.strftime("%d/%m %H:%M")
            except:
                display_date = row['published_at'][:16]

            # בחירת צבעים
            sev_class = "tag-critical" if row['severity']=='Critical' else ("tag-high" if row['severity']=='High' else "tag-medium")
            cat_class = "tag-israel" if row['category']=='Israel Focus' else "tag-medium"
            
            st.markdown(f"""
            <div class="report-card">
                <div style="display:flex; align-items:center; margin-bottom:8px;">
                    <span class="tag tag-time">🕒 {display_date}</span>
                    <span class="tag {sev_class}">{row['severity']}</span>
                    <span class="tag {cat_class}">{row['category']}</span>
                </div>
                <h4 style="margin:8px 0; font-size:1.2rem;">{row['title']}</h4>
                <p style="color:#ccc; margin-bottom:10px;">{row['summary']}</p>
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <small style="color:#888">Source: {row['source']}</small>
                    <a href="{row['url']}" target="_blank" style="padding:5px 10px; background:#333; border-radius:5px;">Read Full Article ↗</a>
                </div>
            </div>""", unsafe_allow_html=True)

with tab_tools:
    st.markdown("<div class='tool-box'><h3>🛠️ Analyst Investigation Suite</h3><p>Enter an IOC to scan across all connected engines. Results will appear below.</p></div>", unsafe_allow_html=True)
    
    ioc_col, btn_col = st.columns([4,1])
    ioc_input = ioc_col.text_input("Enter Indicator (IP / Domain / Hash)", placeholder="e.g. 1.1.1.1 or evil.com")
    
    # 1. SCAN ACTION
    if btn_col.button("🔍 Scan IOC", use_container_width=True):
        if not ioc_input:
            st.warning("Please enter an indicator.")
        else:
            st.session_state.current_ioc = ioc_input
            st.session_state.ioc_data = {} # Reset data
            
            with st.status("Running Investigation Tools...", expanded=True) as status:
                # Load Secrets
                try: vt_key = st.secrets["vt_key"]
                except: vt_key = ""
                try: abuse_key = st.secrets["abuseipdb_key"]
                except: abuse_key = ""
                try: urlscan_key = st.secrets["urlscan_key"]
                except: urlscan_key = ""
                
                tl = ThreatLookup(vt_key=vt_key, urlscan_key=urlscan_key, abuse_ch_key="")
                
                # Run Checks
                st.write("Checking VirusTotal...")
                vt_res = tl.query_virustotal(ioc_input)
                
                st.write("Checking AbuseIPDB...")
                # Simple logic: check if it looks like an IP
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc_input):
                    ab_res = tl.query_abuseipdb(ioc_input, abuse_key)
                else:
                    ab_res = {"status": "skipped", "msg": "Not an IP"}
                
                st.write("Checking ThreatFox & URLhaus...")
                tf_res = tl.query_threatfox(ioc_input)
                uh_res = tl.query_urlhaus(ioc_input)
                
                # Save Data
                st.session_state.ioc_data = {
                    "virustotal": vt_res,
                    "abuseipdb": ab_res,
                    "threatfox": tf_res,
                    "urlhaus": uh_res
                }
                status.update(label="Scan Complete!", state="complete", expanded=False)

    # 2. DISPLAY RAW RESULTS
    if st.session_state.ioc_data:
        st.divider()
        st.subheader(f"📊 Results for: {st.session_state.current_ioc}")
        
        # Display in Tabs
        t1, t2, t3, t4 = st.tabs(["VirusTotal", "AbuseIPDB", "ThreatFox", "URLhaus"])
        
        with t1:
            vt = st.session_state.ioc_data.get('virustotal', {})
            if vt.get('status') == 'found':
                stats = vt.get('stats', {})
                col1, col2 = st.columns(2)
                col1.metric("Malicious", stats.get('malicious', 0), delta_color="inverse")
                col1.metric("Suspicious", stats.get('suspicious', 0), delta_color="inverse")
                col2.json(stats)
            else:
                st.info(f"VirusTotal Status: {vt.get('status', 'Unknown')}")

        with t2:
            ab = st.session_state.ioc_data.get('abuseipdb', {})
            if ab.get('success'):
                d = ab['data']
                st.metric("Abuse Score", f"{d.get('abuseConfidenceScore')}%")
                st.write(f"**ISP:** {d.get('isp')} ({d.get('countryCode')})")
                st.write(f"**Usage:** {d.get('usageType')}")
            else:
                st.info(ab.get('error', 'Not Applicable'))

        with t3:
            st.json(st.session_state.ioc_data.get('threatfox', {}))
            
        with t4:
            st.json(st.session_state.ioc_data.get('urlhaus', {}))

        # 3. AI SUMMARY ACTION
        st.divider()
        if gemini_key:
            if st.button("✨ Analyze Findings with AI Analyst", type="primary"):
                with st.spinner("AI Analyst is reading the reports..."):
                    proc = AIBatchProcessor(gemini_key)
                    # Prepare context
                    context = {
                        "ioc": st.session_state.current_ioc,
                        "raw_data": st.session_state.ioc_data
                    }
                    report = asyncio.run(proc.analyze_single_ioc(st.session_state.current_ioc, context))
                    
                    st.markdown("---")
                    st.markdown("### 🤖 Incident Report")
                    st.markdown(report)
        else:
            st.warning("Please enter Gemini API Key in sidebar to enable AI analysis.")
