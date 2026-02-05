import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import datetime
import pytz
import streamlit.components.v1 as components
from utils import *
from dateutil import parser as date_parser
from streamlit_autorefresh import st_autorefresh

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
    
    /* RTL Specific Style */
    .rtl-content {
        direction: rtl;
        text-align: right;
    }

    .card-title { font-weight: 700; font-size: 1.15rem; color: #111; margin-bottom: 8px; }
    .card-summary { color: #444; font-size: 0.95rem; margin-bottom: 10px; line-height: 1.5; }
    
    .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; margin-right: 6px; }
    .tag-critical { background: #fee2e2; color: #991b1b; }
    .tag-incd { background: #1e3a8a; color: #fff; }
    .tag-time { background: #f3f4f6; color: #666; }
    
    a { text-decoration: none; color: #2563eb; font-weight: bold; }
    
    div[role="radiogroup"] { display: flex; gap: 8px; flex-wrap: wrap; }
    div[role="radiogroup"] label {
        background-color: #f8f9fa; border: 1px solid #dee2e6; border-radius: 6px; padding: 4px 12px; transition: all 0.2s; font-size: 0.9rem;
    }
    div[role="radiogroup"] label[data-checked="true"] {
        background-color: #0f172a; color: white; border-color: #0f172a;
    }
    div[role="radiogroup"] label > div:first-child { display: none; }
    
    .tool-btn {
        display: inline-block;
        padding: 6px 12px;
        margin: 4px;
        background-color: #eef2ff;
        border: 1px solid #c7d2fe;
        border-radius: 6px;
        color: #3730a3;
        font-weight: 600;
        font-size: 0.85rem;
        text-decoration: none !important;
        transition: background-color 0.2s;
    }
    .tool-btn:hover {
        background-color: #e0e7ff;
        color: #312e81;
    }
</style>
""", unsafe_allow_html=True)

# --- INITIALIZATION ---
init_db() 
IL_TZ = pytz.timezone('Asia/Jerusalem')
REFRESH_MINUTES = 15

# --- AUTO-REFRESH COMPONENT (TRIGGERS RERUN EVERY X MIN) ---
# This forces the script to rerun every 15 minutes, allowing us to check if update is needed
st_autorefresh(interval=REFRESH_MINUTES * 60 * 1000, key="data_refresh")

GROQ_KEY = st.secrets.get("groq_key", "")
VT_KEY = st.secrets.get("vt_key", "")
URLSCAN_KEY = st.secrets.get("urlscan_key", "")
ABUSE_KEY = st.secrets.get("abuseipdb_key", "")

# --- UPDATE LOGIC FUNCTION ---
async def perform_update():
    col, proc = CTICollector(), AIBatchProcessor(GROQ_KEY)
    raw = await col.get_all_data()
    if raw:
        analyzed = await proc.analyze_batch(raw)
        return save_reports(raw, analyzed)
    return 0

# --- AUTO-LOAD & UPDATE CHECK ---
if "last_run" not in st.session_state:
    # First Load
    st.session_state["last_run"] = datetime.datetime.now(IL_TZ)
    with st.spinner("🚀 Initializing CTI Feeds..."):
        asyncio.run(perform_update())

else:
    # Check if interval passed
    now = datetime.datetime.now(IL_TZ)
    last_run = st.session_state["last_run"]
    if (now - last_run).total_seconds() > (REFRESH_MINUTES * 60):
        # Time to update!
        with st.spinner("🔄 Auto-updating feeds..."):
            asyncio.run(perform_update())
            st.session_state["last_run"] = now
            st.toast("Feeds updated automatically!", icon="🔄")


# --- SIDEBAR ---
with st.sidebar:
    st.header("⚙️ System Status")
    ok, msg = ConnectionManager.check_groq(GROQ_KEY)
    st.write(f"Groq AI: {'✅' if ok else '❌'} ({msg})")
    
    st.divider()
    
    if st.button("🚀 Force Global Update", type="primary"):
        with st.status("Fetching New Intelligence...", expanded=True):
            count = asyncio.run(perform_update())
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
    
    # Merge
    df_final = pd.concat([df_incd.head(8), df_others]).sort_values(by='published_at', ascending=False).drop_duplicates(subset=['url'])
    
    if df_final.empty:
        st.info("No active threats found. Try 'Force Global Update'.")
    else:
        # --- FILTERS SECTION ---
        st.write("##### 🕵️ Filter Intelligence")
        
        # Calculate Counts
        cnt_all = len(df_final)
        cnt_incd = len(df_final[df_final['source'] == 'INCD'])
        cnt_global = len(df_final[df_final['source'] != 'INCD'])
        
        cnt_crit = len(df_final[df_final['severity'].str.contains('Critical|High', case=False, na=False)])
        cnt_med = len(df_final[df_final['severity'].str.contains('Medium', case=False, na=False)])
        cnt_info = len(df_final[df_final['severity'].str.contains('Low|Info|News', case=False, na=False)])

        c_src, c_sev = st.columns([1, 2])
        
        with c_src:
            st.caption("Source")
            filter_source = st.radio(
                "Source Filter", 
                [f"All ({cnt_all})", f"INCD ({cnt_incd})", f"Global ({cnt_global})"], 
                horizontal=True, 
                label_visibility="collapsed"
            )
        
        with c_sev:
            st.caption("Severity")
            filter_sev = st.radio(
                "Severity Filter", 
                [f"All", f"Critical ({cnt_crit})", f"Medium ({cnt_med})", f"Info ({cnt_info})"], 
                horizontal=True, 
                label_visibility="collapsed"
            )

        # Apply Filters
        df_display = df_final.copy()
        
        # 1. Source Filter
        if "INCD" in filter_source:
            df_display = df_display[df_display['source'] == 'INCD']
        elif "Global" in filter_source:
            df_display = df_display[df_display['source'] != 'INCD']
            
        # 2. Severity Filter
        if "Critical" in filter_sev:
            df_display = df_display[df_display['severity'].str.contains('Critical|High', case=False, na=False)]
        elif "Medium" in filter_sev:
            df_display = df_display[df_display['severity'].str.contains('Medium', case=False, na=False)]
        elif "Info" in filter_sev:
             df_display = df_display[df_display['severity'].str.contains('Low|Info|News', case=False, na=False)]

        st.divider()

        for _, row in df_display.iterrows():
            # Parse Date
            try:
                dt = date_parser.parse(row['published_at'])
                if dt.tzinfo is None: dt = pytz.utc.localize(dt).astimezone(IL_TZ)
                else: dt = dt.astimezone(IL_TZ)
                date_str = dt.strftime('%d/%m %H:%M')
            except: date_str = "Unknown"

            sev_class = "tag-critical" if "Critical" in row['severity'] else ""
            
            # CUSTOM LOGIC FOR INCD
            if row['source'] == "INCD":
                source_display = "מערך הסייבר"
                source_tag_class = "tag-incd"
                rtl_class = "rtl-content"
            else:
                source_display = row['source']
                source_tag_class = "tag-time"
                rtl_class = ""
            
            st.markdown(f"""
            <div class="report-card">
                <div style="margin-bottom: 8px; direction: ltr;">
                    <span class="tag {source_tag_class}">{source_display}</span>
                    <span class="tag tag-time">{date_str}</span>
                    <span class="tag {sev_class}">{row['severity']}</span>
                    <span class="tag tag-time">{row['category']}</span>
                </div>
                <div class="card-title {rtl_class}">{row['title']}</div>
                <div class="card-summary {rtl_class}">{row['summary']}</div>
                <div style="font-size: 0.85rem; margin-top: 10px; text-align: left; direction: ltr;">
                    <a href="{row['url']}" target="_blank">🔗 Read Full Report</a>
                </div>
            </div>
            """, unsafe_allow_html=True)

# --- TAB 2: SOC TOOLBOX ---
with tab_tools:
    st.subheader("🛠️ SOC Toolbox - IOC Investigation")
    
    c_input, c_btn = st.columns([4, 1])
    with c_input:
        ioc_input = st.text_input("Enter Indicator", placeholder="e.g., 1.2.3.4, evil.com, http://bad-site.com/login").strip()
    with c_btn:
        st.write("") 
        st.write("") 
        btn_scan = st.button("Investigate 🕵️")

    if btn_scan and ioc_input:
        ioc_type = identify_ioc_type(ioc_input)
        
        if not ioc_type:
            st.error("❌ Invalid Input! Please enter a valid IP, Domain, Hash or URL.")
        else:
            st.success(f"Identified Type: {ioc_type.upper()}")
            tl = ThreatLookup(VT_KEY, URLSCAN_KEY, ABUSE_KEY)
            results = {}
            
            with st.status("Scanning External Sources...", expanded=True):
                st.write("Querying VirusTotal...")
                vt_data = tl.query_virustotal(ioc_input, ioc_type)
                results['virustotal'] = vt_data if vt_data else "No Data"
                
                if ioc_type in ["domain", "url", "ip"]:
                    st.write("Querying URLScan.io...")
                    us_data = tl.query_urlscan(ioc_input)
                    results['urlscan'] = us_data if us_data else "No Data"
                
                if ioc_type == "ip":
                    st.write("Querying AbuseIPDB...")
                    ab = tl.query_abuseipdb(ioc_input)
                    results['abuseipdb'] = ab if ab else "No Data"
                    
            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown("### 🦠 VirusTotal")
                if isinstance(results.get('virustotal'), dict):
                    # VT Data structure
                    attrs = results['virustotal'].get('attributes', {})
                    rels = results['virustotal'].get('relationships', {})
                    
                    stats = attrs.get('last_analysis_stats', {})
                    malicious = stats.get('malicious', 0)
                    color = "red" if malicious > 0 else "green"
                    st.markdown(f":{color}[**Detections: {malicious}**]")
                    
                    # 1. Metadata
                    with st.expander("🔍 Metadata & Tags", expanded=False):
                        if attrs.get('country'):
                            st.write(f"**Country:** {attrs.get('country')} 🌍")
                        if attrs.get('as_owner'):
                            st.write(f"**AS Owner:** {attrs.get('as_owner')} ({attrs.get('asn', '')})")

                        st.write(f"**Reputation:** {attrs.get('reputation', 0)}")
                        st.write(f"**Tags:** {', '.join(attrs.get('tags', []))}")
                        if attrs.get('creation_date'):
                            st.write(f"**Created:** {datetime.datetime.fromtimestamp(attrs['creation_date']).strftime('%Y-%m-%d')}")
                    
                    # 2. Relations (Network)
                    with st.expander("🕸️ Network Relations", expanded=False):
                         # Resolutions (Passive DNS)
                         if rels.get('resolutions'):
                             st.write("**Passive DNS (Domains on this IP):**")
                             for r in rels['resolutions'].get('data', [])[:8]:
                                 st.code(r.get('attributes', {}).get('host_name', 'Unknown'))
                                 
                         if rels.get('contacted_urls'):
                             st.write("**Contacted URLs:**")
                             for u in rels['contacted_urls'].get('data', [])[:5]:
                                 st.code(u.get('context_attributes', {}).get('url', u.get('id', '')))
                         
                         if rels.get('contacted_ips'):
                             st.write("**Contacted IPs:**")
                             for ip in rels['contacted_ips'].get('data', [])[:5]:
                                 st.code(ip.get('id'))
                                 
                    # 3. Engines
                    with st.expander("📊 Engine Detection", expanded=False):
                        st.json(stats)
                        
                else: st.write("N/A")
                
            with c2:
                st.markdown("### 🌐 URLScan")
                if isinstance(results.get('urlscan'), dict):
                    # Data from Full Result API
                    task = results['urlscan'].get('task', {})
                    verdict = results['urlscan'].get('verdict', {}).get('overall', 'Unknown')
                    
                    st.write(f"**Target:** `{task.get('url', 'Unknown')}`")
                    st.write(f"**Verdict:** {verdict}")
                    
                    if results['urlscan'].get('page', {}).get('country'):
                         st.write(f"**Location:** {results['urlscan']['page']['country']}")
                    
                    # Screenshot
                    if task.get('screenshotURL'): 
                        st.image(task['screenshotURL'])
                    
                    with st.expander("See Raw Data"):
                        st.json(results['urlscan'].get('page', {}))
                else: st.write("N/A")
                
            with c3:
                st.markdown("### 🛑 AbuseIPDB")
                if ioc_type == 'ip' and isinstance(results.get('abuseipdb'), dict):
                    score = results['abuseipdb'].get('abuseConfidenceScore', 0)
                    st.metric("Abuse Score", f"{score}%")
                    st.write(f"ISP: {results['abuseipdb'].get('isp')}")
                    st.write(f"Usage: {results['abuseipdb'].get('usageType')}")
                else: st.write("N/A")

            st.divider()
            st.subheader("🤖 AI Analyst Assessment (Tier 3)")
            with st.spinner("Generating Enterprise Defense Playbook..."):
                proc = AIBatchProcessor(GROQ_KEY)
                report = asyncio.run(proc.analyze_single_ioc(ioc_input, ioc_type, results))
                st.markdown(report)

# --- TAB 3: STRATEGIC INTEL ---
with tab_strat:
    st.subheader("🧠 Strategic Threat Intel - Campaign Profiler")
    st.markdown("Deep dive into active Threat Actors targeting **Israel** & the Middle East.")
    
    threats = APTSheetCollector().fetch_threats()
    actor_names = [t['name'] for t in threats]
    
    # --- ACTOR SELECTOR ---
    selected_actor_name = st.selectbox("Select Threat Actor:", actor_names)
    actor_data = next(t for t in threats if t['name'] == selected_actor_name)
    
    col_prof, col_acts = st.columns([2, 1])
    
    # --- LEFT COLUMN: PROFILE ---
    with col_prof:
        st.markdown(f"### 👹 {actor_data['name']}")
        st.markdown(f"**Origin:** {actor_data['origin']} | **Type:** {actor_data['type']}")
        st.info(f"**Description:** {actor_data['desc']}")
        
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**🛠️ Tools & Malware**")
            for tool in actor_data['tools'].split(','):
                st.code(tool.strip(), language="text")
        with c2:
            st.markdown("**🏗️ MITRE ATT&CK**")
            for tech in actor_data['mitre'].split(','):
                st.code(tech.strip(), language="text")
        
        st.markdown("---")
        st.markdown("#### 🔗 External Intelligence (Curated)")
        st.markdown(f"- [Malpedia Profile]({actor_data['malpedia']})")
        st.markdown(f"- [MITRE Groups Search](https://attack.mitre.org/search/?q={actor_data['name'].split()[0]})")
        st.markdown(f"- [Google APT Search](https://cse.google.com/cse?cx=003248445720253387346:turlh5vi4xc&q={actor_data['name']})")
        
    # --- RIGHT COLUMN: ACTIONS ---
    with col_acts:
        st.markdown("### ⚡ Operational Actions")
        if st.button(f"🏹 Generate Hunting Queries", key="hunt_btn"):
            proc = AIBatchProcessor(GROQ_KEY)
            with st.spinner(f"Generating detection rules for {actor_data['name']}..."):
                res = asyncio.run(proc.generate_hunting_queries(actor_data))
                with st.expander("View XQL / YARA Rules", expanded=True):
                    st.markdown(res)
                    
        st.write("")
        st.markdown("### 📰 Recent Activity (Simulated)")
        st.caption("Latest reports linked to this actor:")
        st.markdown(f"""
        * 12/2025: [{actor_data['name']} New Phishing Campaign targeting Finance](https://www.gov.il/he/departments/topics/cyber-attack-network)
        * 11/2025: [Indicator release: {actor_data['tools'].split(',')[0]} variant](https://unit42.paloaltonetworks.com/)
        """)

    # --- ANALYST TOOLKIT SECTION (FROM README) ---
    st.markdown("---")
    st.subheader("🧰 CTI Analyst Toolkit (Quick Links)")
    st.markdown("Essential tools curated from *Awesome Threat Intelligence* list.")
    
    toolkit = AnalystToolkit.get_tools()
    
    for category, tools in toolkit.items():
        st.markdown(f"**{category}**")
        cols = st.columns(len(tools))
        for idx, tool in enumerate(tools):
            with cols[idx]:
                st.markdown(f"""
                <a href="{tool['url']}" target="_blank" class="tool-btn">{tool['name']}</a>
                <div style="font-size: 0.8em; color: #666; margin-top: 4px; margin-left: 6px;">{tool['desc']}</div>
                """, unsafe_allow_html=True)
        st.write("")

# --- TAB 4: MAP ---
with tab_map:
    components.iframe("https://threatmap.checkpoint.com/", height=600)
