import streamlit as st
import asyncio
from utils import init_db, CTICollector, AIBatchProcessor, save_reports, DB_NAME
import pandas as pd
from streamlit_autorefresh import st_autorefresh
import sqlite3

st.set_page_config(page_title="SOC War Room", layout="wide")
st_autorefresh(interval=15 * 60 * 1000, key="auto_refresh") # 15 min refresh

init_db()

st.title("🛡️ SOC Threat Intelligence - Real-Time")

api_key = st.sidebar.text_input("Gemini API Key", type="password")

async def sync_data():
    if not api_key:
        st.error("Missing API Key")
        return
    with st.spinner("Analyzing Intelligence (Target < 60s)..."):
        collector = CTICollector()
        processor = AIBatchProcessor(api_key)
        
        # 1. Fetch
        raw_data = await collector.get_all_data()
        # 2. Batch AI Analysis
        analysis = await processor.analyze_batch(raw_data)
        # 3. Save
        save_reports(raw_data, analysis)
        st.success("Analysis Complete")

if st.sidebar.button("Run Global Scan"):
    asyncio.run(sync_data())

# Data Visualization
conn = sqlite3.connect(DB_NAME)
df = pd.read_sql_query("SELECT * FROM intel_reports ORDER BY published_at DESC", conn)
conn.close()

if not df.empty:
    cols = st.columns(3)
    cols[0].metric("Total Threats", len(df))
    cols[1].metric("Israel Focused", len(df[df['category'] == 'Israel Focus']))
    cols[2].metric("Critical Vulns", len(df[df['category'] == 'Vulnerability']))

    st.subheader("Intelligence Feed (Last 24h)")
    for _, row in df.iterrows():
        with st.expander(f"[{row['category']}] {row['title']} - {row['source']}"):
            st.write(f"**Country:** {row['country']}")
            st.write(f"**Insight:** {row['summary']}")
            st.link_button("View Original Report", row['url'])
else:
    st.info("No threats detected. Click 'Run Global Scan' in the sidebar.")
