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

# --- UI STYLING ---
st.markdown("""
<style>
    .report-card { background-color: #fff; padding: 15px; border-radius: 8px; border-left: 5px solid #333; margin-bottom: 10px; color: #111 !important; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    .card-title { font-weight: bold; font-size: 1.1rem; color: #000 !important; margin: 5px 0; }
    .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-right: 5px; }
    .tag-critical { background: #ffcccc; color: #990000; }
    .tag-incd { background: #000080; color: #ffffff; border: 1px solid #ffffff; } /* Special INCD Tag */
    .tag-israel { background: #cce5ff; color: #004085; }
    .tag-time { background: #f0f0f0; color: #666; }
    a { text-decoration: none; color: #0066cc !important; font-weight: bold; }
    .stButton>button { width: 100%; }
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
    st.header("⚙️ Status")
    ok, msg = ConnectionManager.check_groq(GROQ_KEY)
    st.write(f"Groq AI: {'✅' if ok else '❌'} ({msg})")
    
    if st.button("🚀 Force Global Update", type="primary"):
        with st.status("Fetching New Intelligence...", expanded=True):
            async def run_update():
                col, proc = CTICollector(), AIBatchProcessor(GROQ_KEY)
                st.write("Connecting to sources (RSS, Telegram, Gov.il)...")
                raw = await col.get_all_data()
                if not raw: 
                    st.warning("No new raw data found.")
                    return 0
                st.write(f"Analyzing {len(raw)} items with AI...")
                analyzed = await proc.analyze_batch(raw)
                return save_reports(raw, analyzed)
            count = asyncio.run(run_update())
            st.success(f"Discovered {count} new items.")
            st.rerun()

# --- MAIN TABS ---
tab_feed, tab_tools, tab_strat, tab_map = st.tabs(["🔴 Live Feed", "🛠️ SOC Toolbox", "🧠 Strategic Intel", "🌍 Global Map"])

# --- TAB 1: LIVE FEED ---
with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    
    # LOGIC: 
    # 1. Fetch INCD items separately (Rule: Last 4 OR < 96 hours)
    # 2. Fetch Regular items (< 48 hours)
    
    df_incd = pd.read_sql_query("""
        SELECT * FROM intel_reports 
        WHERE source = 'INCD' 
        ORDER BY published_at DESC
    """, conn)
    
    df_others = pd.read_sql_query("""
        SELECT * FROM intel_reports 
        WHERE source != 'INCD' AND published_at > datetime('now', '-2 days')
        ORDER BY published_at DESC
    """, conn)
    
    conn.close()
    
    # Filter INCD in Python for complex logic (Last 4 OR < 96h)
    now_ts = pd.Timestamp.now(tz=IL_TZ)
    
    if not df_incd.empty:
        # Convert to datetime
        df_incd['dt'] = pd.to_datetime(df_incd['published_at'], utc=True).dt.tz_convert(IL_TZ)
        # Condition 1: Less than 4 days
        cond_time = (now_ts - df_incd['dt']).dt.total_seconds() < (96 * 3600)
        # Condition 2: Is it in the top 4? (Since it's sorted DESC, indices 0-3 are top 4)
        df_incd_filtered = df_incd[cond_time | (df_incd.index < 4)].copy()
    else:
        df_incd_filtered = df_incd

    # Combine
    if not df_others.empty:
         df_others['dt'] = pd.to_datetime(df_others['published_at'], utc=True).dt.tz_convert(IL_TZ)
    
    df_final = pd.concat([df_incd_filtered, df_others]).sort_values(by='published_at', ascending=False).drop_duplicates(subset=['url'])
    
    if df_final.empty:
        st.info("No active threats found. Use Force Update.")
    else:
        for _, row in df_final.iterrows():
            pub_date = row['dt']
            
            # Styling Logic
            sev_class = "tag-critical" if "Critical" in row['severity'] else ""
            source_tag = "tag-incd" if row['source'] == "INCD" else "tag-time"
            
            st.markdown(f"""
            <div class="report-card">
                <span class="tag {source_tag}">{row['source']}</span>
                <span class="tag tag-time">{pub_date.strftime('%d/%m %H:%M')}</span>
                <span class="tag {sev_class}">{row['severity']}</span>
                <span class="tag">{row['category']}</span>
                <div class="card-title">{row['title']}</div>
                <div style="margin: 5px 0; color: #333;">{row['summary']}</div>
                <div style="font-size: 0.8rem; color: #666;"><a href="{row['url']}" target="_blank">🔗 Open Original Report</a></div>
            </div>
            """, unsafe_allow_html=True)

# --- TAB 2: SOC TOOLBOX ---
with tab_tools:
    st.subheader("🛠️ SOC Toolbox - IOC Investigation")
    st.info("Supported: IPv4, IPv6, Domains, Hashes (MD5/SHA)")
    
    c_input, c_btn = st.columns([4, 1])
    with c_input:
        ioc_input = st.text_input("Enter Indicator", placeholder="e.g., 1.2.3.4, evil.com, a1b2...").strip()
    with c_btn:
        st.write("") # Spacer
        st.write("") 
        btn_scan = st.button("Investigate 🕵️")

    if btn_scan and ioc_input:
        ioc_type = identify_ioc_type(ioc_input)
        
        if not ioc_type:
            st.error("❌ Invalid Input! Please enter a valid IP, Domain, or Hash.")
        else:
            st.success(f"Identified: {ioc_type.upper()}")
            tl = ThreatLookup(VT_KEY, URLSCAN_KEY, ABUSE_KEY)
            results = {}
            
            # 1. SCANNING
            with st.status("Scanning External Sources...", expanded=True):
                # VT
                st.write("Querying VirusTotal...")
                vt = tl.query_virustotal(ioc_input, ioc_type)
                results['virustotal'] = vt if vt else "No Data"
                
                # URLScan (Domains only)
                if ioc_type == "domain":
                    st.write("Querying URLScan.io...")
                    us = tl.query_urlscan(ioc_input)
                    results['urlscan'] = us if us else "No Data"
                
                # AbuseIPDB (IPs only)
                if ioc_type == "ip":
                    st.write("Querying AbuseIPDB...")
                    ab = tl.query_abuseipdb(ioc_input)
                    results['abuseipdb'] = ab if ab else "No Data"
                    
            # 2. RAW RESULTS DISPLAY
            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown("### 🦠 VirusTotal")
                if isinstance(results.get('virustotal'), dict):
                    stats = results['virustotal'].get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    color = "red" if malicious > 0 else "green"
                    st.markdown(f":{color}[**Detections: {malicious}**]")
                    st.json(stats)
                else: st.write("N/A")
                
            with c2:
                st.markdown("### 🌐 URLScan/Reputation")
                if ioc_type == 'domain' and isinstance(results.get('urlscan'), dict):
                    st.write(f"Verdict: {results['urlscan'].get('verdict', {}).get('overall', 'Unknown')}")
                    if results['urlscan'].get('screenshot'): st.image(results['urlscan']['screenshot'])
                else: st.write("N/A for this type")
                
            with c3:
                st.markdown("### 🛑 AbuseIPDB")
                if ioc_type == 'ip' and isinstance(results.get('abuseipdb'), dict):
                    score = results['abuseipdb'].get('abuseConfidenceScore', 0)
                    st.metric("Abuse Confidence", f"{score}%")
                    st.write(f"ISP: {results['abuseipdb'].get('isp')}")
                else: st.write("N/A for this type")

            # 3. AI ANALYSIS
            st.divider()
            st.subheader("🤖 Tier 3 AI Analyst Assessment")
            with st.spinner("Consulting AI Mentor..."):
                proc = AIBatchProcessor(GROQ_KEY)
                report = asyncio.run(proc.analyze_single_ioc(ioc_input, ioc_type, results))
                st.markdown(report)

# --- TAB 3: STRATEGIC INTEL ---
with tab_strat:
    st.subheader("🧠 Strategic Threat Intel - Active Campaigns")
    st.markdown("Focus: **Iran & Middle East** | Targets: **Israel**")
    
    threats = APTSheetCollector().fetch_threats()
    
    for actor in threats:
        with st.expander(f"👹 {actor['name']} ({actor['origin']}) - {actor['type']}"):
            col_desc, col_acts = st.columns([2, 1])
            with col_desc:
                st.markdown(f"**Description:** {actor['desc']}")
                st.markdown(f"**Known Tools:** `{actor['tools']}`")
                st.markdown(f"**MITRE:** `{actor['mitre']}`")
            with col_acts:
                if st.button(f"🏹 Generate Hunting Queries ({actor['name']})"):
                    proc = AIBatchProcessor(GROQ_KEY)
                    with st.spinner("Generating XQL & YARA-L..."):
                        res = asyncio.run(proc.generate_hunting_queries(actor))
                        st.markdown(res)
    
    st.divider()
    st.subheader("🔥 Trending IOCs (AI Curated)")
    st.info("Latest indicators observed in Anti-Israel campaigns (Simulated Live Data)")
    # This section would ideally be dynamic. For now, static placeholders for the UI structure.
    st.markdown("""
    | Indicator | Type | Actor | Confidence |
    |-----------|------|-------|------------|
    | `185.200.118.55` | IP | MuddyWater | High |
    | `update-win-srv.com` | Domain | OilRig | Medium |
    | `0a8b9c...2d1` | SHA256 | Agonizing Serpens | Critical |
    """)

# --- TAB 4: MAP ---
with tab_map:
    components.iframe("https://threatmap.checkpoint.com/", height=600)
