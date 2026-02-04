import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import datetime
import pytz
import streamlit.components.v1 as components
from utils import *
from dateutil import parser as date_parser

# --- CONFIGURATION ---
st.set_page_config(page_title="CTI War Room", layout="wide", page_icon="🛡️")

# --- UI STYLING ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Roboto', sans-serif;
    }
    
    .report-card { 
        background-color: #ffffff; 
        padding: 15px 20px; 
        border-radius: 8px; 
        border-left: 5px solid #333; 
        margin-bottom: 15px; 
        box-shadow: 0 2px 5px rgba(0,0,0,0.05);
    }
    
    .card-title { font-weight: 700; font-size: 1.15rem; color: #111; margin-bottom: 8px; }
    .card-summary { color: #444; font-size: 0.95rem; margin-bottom: 10px; line-height: 1.5; }
    
    .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-right: 6px; }
    .tag-critical { background: #fee2e2; color: #991b1b; }
    .tag-incd { background: #1e3a8a; color: #fff; }
    .tag-time { background: #f3f4f6; color: #666; }
    
    a { text-decoration: none; color: #2563eb; font-weight: bold; }
    
    div[role="radiogroup"] { display: flex; gap: 10px; flex-wrap: wrap; }
    div[role="radiogroup"] label {
        background-color: #fff; border: 1px solid #ddd; border-radius: 20px; padding: 5px 15px; transition: all 0.2s;
    }
    div[role="radiogroup"] label[data-checked="true"] {
        background-color: #2563eb; color: white; border-color: #2563eb;
    }
    div[role="radiogroup"] label > div:first-child { display: none; }
</style>
""", unsafe_allow_html=True)

# --- INITIALIZATION ---
init_db() 
IL_TZ = pytz.timezone('Asia/Jerusalem')
REFRESH_MINUTES = 15

GROQ_KEY = st.secrets.get("groq_key", "")
VT_KEY = st.secrets.get("vt_key", "")
URLSCAN_KEY = st.secrets.get("urlscan_key", "")
ABUSE_KEY = st.secrets.get("abuseipdb_key", "")

# --- AUTO-LOAD & UPDATE LOGIC ---
if "last_run" not in st.session_state:
    st.session_state["last_run"] = datetime.datetime.now(IL_TZ)
    # First time load
    with st.spinner("🚀 Initializing CTI Feeds..."):
        async def startup_update():
            col, proc = CTICollector(), AIBatchProcessor(GROQ_KEY)
            raw = await col.get_all_data()
            if raw:
                analyzed = await proc.analyze_batch(raw)
                save_reports(raw, analyzed)
        asyncio.run(startup_update())

# --- SIDEBAR ---
with st.sidebar:
    st.header("⚙️ System Status")
    ok, msg = ConnectionManager.check_groq(GROQ_KEY)
    st.write(f"Groq AI: {'✅' if ok else '❌'} ({msg})")
    
    st.divider()
    
    if st.button("🚀 Force Global Update", type="primary"):
        with st.status("Fetching New Intelligence...", expanded=True):
            async def run_update():
                col, proc = CTICollector(), AIBatchProcessor(GROQ_KEY)
                st.write("Connecting to Sources...")
                raw = await col.get_all_data()
                if not raw: 
                    st.warning("No new data found.")
                    return 0
                st.write(f"Analyzing {len(raw)} items...")
                analyzed = await proc.analyze_batch(raw)
                cnt = save_reports(raw, analyzed)
                return cnt
            count = asyncio.run(run_update())
            st.session_state["last_run"] = datetime.datetime.now(IL_TZ)
            st.success(f"Discovered {count} new items.")
            st.rerun()

# --- MAIN TABS ---
tab_feed, tab_tools, tab_strat, tab_map = st.tabs(["🔴 Live Feed", "🛠️ SOC Toolbox", "🧠 Strategic Intel", "🌍 Global Map"])

# --- TAB 1: LIVE FEED ---
with tab_feed:
    # 1. Update Status with Calc
    last_up = st.session_state["last_run"]
    next_up = last_up + datetime.timedelta(minutes=REFRESH_MINUTES)
    
    c1, c2, c3 = st.columns([2, 2, 4])
    with c1: st.info(f"Last Update: {last_up.strftime('%H:%M')} (IL)")
    with c2: st.warning(f"Next Auto-Update: {next_up.strftime('%H:%M')} (IL)")
    
    st.divider()

    conn = sqlite3.connect(DB_NAME)
    
    # Priority Fetch: INCD top
    df_incd = pd.read_sql_query("SELECT * FROM intel_reports WHERE source = 'INCD' ORDER BY published_at DESC", conn)
    df_others = pd.read_sql_query("SELECT * FROM intel_reports WHERE source != 'INCD' AND published_at > datetime('now', '-2 days') ORDER BY published_at DESC", conn)
    conn.close()
    
    # Merge - ensuring INCD is prioritized if available
    df_final = pd.concat([df_incd.head(8), df_others]).sort_values(by='published_at', ascending=False).drop_duplicates(subset=['url'])
    
    if df_final.empty:
        st.info("No active threats found. Try 'Force Global Update'.")
    else:
        # Filters
        cat_counts = df_final['category'].value_counts()
        radio_labels = [f"All ({len(df_final)})"] + [f"{cat} ({cnt})" for cat, cnt in cat_counts.items()]
        
        st.markdown("##### 📌 Filter by Category")
        selected_label = st.radio("Filters", radio_labels, horizontal=True, label_visibility="collapsed")
        
        if "All" in selected_label:
            df_display = df_final
        else:
            selected_cat = selected_label.split(" (")[0]
            df_display = df_final[df_final['category'] == selected_cat]

        st.write("") 

        for _, row in df_display.iterrows():
            # Parse Date
            try:
                dt = date_parser.parse(row['published_at'])
                if dt.tzinfo is None: dt = pytz.utc.localize(dt).astimezone(IL_TZ)
                else: dt = dt.astimezone(IL_TZ)
                date_str = dt.strftime('%d/%m %H:%M')
            except: date_str = "Unknown"

            sev_class = "tag-critical" if "Critical" in row['severity'] else ""
            
            # CUSTOM TAG LOGIC FOR INCD
            if row['source'] == "INCD":
                source_display = "מערך הסייבר"
                source_tag_class = "tag-incd"
            else:
                source_display = row['source']
                source_tag_class = "tag-time"
            
            st.markdown(f"""
            <div class="report-card">
                <div style="margin-bottom: 8px;">
                    <span class="tag {source_tag_class}">{source_display}</span>
                    <span class="tag tag-time">{date_str}</span>
                    <span class="tag {sev_class}">{row['severity']}</span>
                    <span class="tag tag-time">{row['category']}</span>
                </div>
                <div class="card-title">{row['title']}</div>
                <div class="card-summary">{row['summary']}</div>
                <div style="font-size: 0.85rem;">
                    <a href="{row['url']}" target="_blank">🔗 Read Full Report</a>
                </div>
            </div>
            """, unsafe_allow_html=True)

# --- TAB 2: SOC TOOLBOX ---
with tab_tools:
    st.subheader("🛠️ SOC Toolbox - IOC Investigation")
    
    c_input, c_btn = st.columns([4, 1])
    with c_input:
        ioc_input = st.text_input("Enter Indicator", placeholder="e.g., 1.2.3.4, evil.com").strip()
    with c_btn:
        st.write("") 
        st.write("") 
        btn_scan = st.button("Investigate 🕵️")

    if btn_scan and ioc_input:
        ioc_type = identify_ioc_type(ioc_input)
        
        if not ioc_type:
            st.error("❌ Invalid Input! Please enter a valid IP, Domain, or Hash.")
        else:
            st.success(f"Identified Type: {ioc_type.upper()}")
            tl = ThreatLookup(VT_KEY, URLSCAN_KEY, ABUSE_KEY)
            results = {}
            
            with st.status("Scanning External Sources...", expanded=True):
                st.write("Querying VirusTotal...")
                vt = tl.query_virustotal(ioc_input, ioc_type)
                results['virustotal'] = vt if vt else "No Data"
                
                if ioc_type == "domain":
                    st.write("Querying URLScan.io...")
                    us = tl.query_urlscan(ioc_input)
                    results['urlscan'] = us if us else "No Data"
                
                if ioc_type == "ip":
                    st.write("Querying AbuseIPDB...")
                    ab = tl.query_abuseipdb(ioc_input)
                    results['abuseipdb'] = ab if ab else "No Data"
                    
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
                st.markdown("### 🌐 URLScan")
                if ioc_type == 'domain' and isinstance(results.get('urlscan'), dict):
                    verdict = results['urlscan'].get('verdict', {}).get('overall', 'Unknown')
                    st.write(f"Verdict: **{verdict}**")
                    if results['urlscan'].get('screenshot'): st.image(results['urlscan']['screenshot'])
                else: st.write("N/A")
                
            with c3:
                st.markdown("### 🛑 AbuseIPDB")
                if ioc_type == 'ip' and isinstance(results.get('abuseipdb'), dict):
                    score = results['abuseipdb'].get('abuseConfidenceScore', 0)
                    st.metric("Abuse Score", f"{score}%")
                    st.write(f"ISP: {results['abuseipdb'].get('isp')}")
                else: st.write("N/A")

            st.divider()
            st.subheader("🤖 AI Analyst Assessment (Tier 3)")
            with st.spinner("Generating Report..."):
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
                st.markdown(f"**Tools:** `{actor['tools']}`")
                st.markdown(f"**MITRE:** `{actor['mitre']}`")
            with col_acts:
                if st.button(f"🏹 Generate Hunting Queries ({actor['name']})"):
                    proc = AIBatchProcessor(GROQ_KEY)
                    with st.spinner("Generating XQL & YARA..."):
                        res = asyncio.run(proc.generate_hunting_queries(actor))
                        st.markdown(res)
    
    st.divider()
    st.subheader("🔥 Trending IOCs")
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
