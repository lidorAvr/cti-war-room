import streamlit as st
import asyncio
from utils import init_db, CTICollector, AIBatchProcessor, save_reports, DB_NAME
import pandas as pd
from streamlit_autorefresh import st_autorefresh
import sqlite3
import datetime
from dateutil import parser

# --- Page Config ---
st.set_page_config(page_title="SOC War Room", layout="wide", page_icon="🛡️")

# --- Custom CSS for UI ---
st.markdown("""
<style>
    .report-card {
        background-color: #1E1E1E;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #333;
        margin-bottom: 15px;
    }
    .tag {
        display: inline-block;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.8rem;
        font-weight: bold;
        margin-right: 5px;
    }
    .tag-critical { background-color: #721c24; color: #f8d7da; border: 1px solid #f5c6cb; }
    .tag-high { background-color: #856404; color: #fff3cd; border: 1px solid #ffeeba; }
    .tag-medium { background-color: #0c5460; color: #d1ecf1; border: 1px solid #bee5eb; }
    .tag-israel { background-color: #004085; color: #cce5ff; border: 1px solid #b8daff; }
    .meta-text { color: #888; font-size: 0.8rem; }
    .source-tag { background-color: #333; color: #ddd; padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; }
</style>
""", unsafe_allow_html=True)

st_autorefresh(interval=15 * 60 * 1000, key="auto_refresh")
init_db()

# --- Initialize Session State for Filters ---
if 'filter_type' not in st.session_state:
    st.session_state.filter_type = 'All'

# --- Sidebar ---
with st.sidebar:
    st.header("⚙️ SOC Controls")
    api_key_input = st.text_input("Gemini API Key", type="password")
    api_key = api_key_input.strip() if api_key_input else None
    
    if st.button("🚀 Run Manual Scan"):
        if not api_key:
            st.error("Missing API Key")
        else:
            with st.spinner("Scanning & Analyzing..."):
                async def run_scan():
                    col = CTICollector()
                    proc = AIBatchProcessor(api_key)
                    raw = await col.get_all_data()
                    analyzed = await proc.analyze_batch(raw)
                    return save_reports(raw, analyzed)
                
                new_count = asyncio.run(run_scan())
                st.success(f"Scan Done. Added {new_count} new reports.")
                st.rerun()

    st.divider()
    st.info("System automatically refreshes every 15 minutes.")

# --- Data Loading ---
conn = sqlite3.connect(DB_NAME)
df = pd.read_sql_query("SELECT * FROM intel_reports ORDER BY published_at DESC", conn)
conn.close()

# --- Main Dashboard ---
st.title("🛡️ SOC Threat Intelligence Hub")
st.markdown(f"**Last Update:** {datetime.datetime.now().strftime('%H:%M')} | **Active Threats (24h):** {len(df)}")

# --- Clickable Metrics / Filters ---
# Calculate counts
count_critical = len(df[df['severity'] == 'Critical'])
count_israel = len(df[df['category'] == 'Israel Focus'])
count_all = len(df)

# Custom Filter Buttons
c1, c2, c3, c4 = st.columns(4)
if c1.button(f"🚨 Critical ({count_critical})", use_container_width=True):
    st.session_state.filter_type = 'Critical'
if c2.button(f"🇮🇱 Israel Focused ({count_israel})", use_container_width=True):
    st.session_state.filter_type = 'Israel'
if c3.button(f"🌐 All Threats ({count_all})", use_container_width=True):
    st.session_state.filter_type = 'All'
if c4.button(f"🦠 Malware", use_container_width=True):
    st.session_state.filter_type = 'Malware'

# --- Filtering Logic ---
filtered_df = df.copy()
if st.session_state.filter_type == 'Critical':
    filtered_df = df[df['severity'] == 'Critical']
elif st.session_state.filter_type == 'Israel':
    filtered_df = df[df['category'] == 'Israel Focus']
elif st.session_state.filter_type == 'Malware':
    filtered_df = df[df['category'] == 'Malware']

# --- Feed Rendering ---
st.divider()
st.subheader(f"Feed View: {st.session_state.filter_type}")

if filtered_df.empty:
    st.info("No threats found for this category.")
else:
    for _, row in filtered_df.iterrows():
        # Determine Color Class
        sev_class = "tag-medium"
        if row['severity'] == 'Critical': sev_class = "tag-critical"
        elif row['severity'] == 'High': sev_class = "tag-high"
        
        # Determine Category Class
        cat_class = "tag-israel" if row['category'] == 'Israel Focus' else "tag-medium"

        # Parse Date for Display
        try:
            pub_dt = parser.parse(row['published_at'])
            display_date = pub_dt.strftime("%d/%m %H:%M")
        except:
            display_date = row['published_at']

        # HTML Card Construction
        html_card = f"""
        <div class="report-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <div>
                    <span class="tag {sev_class}">{row['severity'].upper()}</span>
                    <span class="tag {cat_class}">{row['category']}</span>
                    <span class="source-tag">{row['source']}</span>
                </div>
                <div class="meta-text">🕒 {display_date}</div>
            </div>
            <h4 style="margin: 5px 0; color: #eee;">{row['title']}</h4>
            <p style="color: #bbb; margin-bottom: 8px;">{row['summary']}</p>
            <div style="display: flex; justify-content: space-between; align-items: flex-end;">
                <div style="font-size: 0.85rem; color: #aaa;">
                    <strong>💥 Impact:</strong> <span style="color: #fff;">{row['impact']}</span>
                </div>
                <a href="{row['url']}" target="_blank" style="text-decoration: none; color: #4da6ff; font-weight: bold;">Read Source ↗</a>
            </div>
        </div>
        """
        st.markdown(html_card, unsafe_allow_html=True)
