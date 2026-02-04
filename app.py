import streamlit as st
import asyncio
import pandas as pd
from streamlit_autorefresh import st_autorefresh
# טוען את כל המחלקות מהקובץ המתוקן
from utils import * st.set_page_config(page_title="SOC War Room", layout="wide", page_icon="🛡️")
st_autorefresh(interval=15 * 60 * 1000, key="auto_refresh")
init_db()

if 'filter_type' not in st.session_state: st.session_state.filter_type = 'All'

st.title("🛡️ SOC War Room")

# --- SIDEBAR: KEY DEBUGGING ---
with st.sidebar:
    st.header("🔧 API Configuration")
    
    # תיבת טקסט למפתח - זה הפתרון הכי בטוח כרגע
    # תדביק את המפתח שלך כאן בממשק
    gemini_key = st.text_input("Gemini API Key:", type="password")
    
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
    
    if st.button("🚀 Run Scan"):
        with st.spinner("Analyzing..."):
            # Dummy data for test
            dummy_data = [{"title": "Test Threat", "url": "http://evil.com", "date": "2024-01-01", "source": "Test", "summary": "This is a test malware."}]
            proc = AIBatchProcessor(gemini_key)
            analyzed = asyncio.run(proc.analyze_batch(dummy_data))
            st.write(analyzed)
            st.success("Scan Logic Finished")

# --- TABS ---
tab1, tab2 = st.tabs(["Feed", "Tools"])

with tab1:
    st.info("Feed will appear here after database connection.")

with tab2:
    ioc = st.text_input("Check IOC (e.g., 1.1.1.1)")
    if st.button("Analyze IOC"):
        if gemini_key:
            proc = AIBatchProcessor(gemini_key)
            with st.spinner("Asking AI..."):
                res = asyncio.run(proc.analyze_single_ioc(ioc, {"raw": "data"}))
                st.markdown(res)
        else:
            st.error("Enter API Key first.")
