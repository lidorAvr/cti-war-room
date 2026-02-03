import streamlit as st
import pandas as pd
import pydeck as pdk
import plotly.express as px
import asyncio
import time
from utils import init_db, DataCollector, get_all_intel, get_coords

# --- Config & Styling ---
st.set_page_config(page_title="CTI WAR ROOM", page_icon="🛡️", layout="wide")

st.markdown("""
    <style>
    .stApp { background-color: #0e1117; color: #00ff41; }
    .metric-card { background-color: #161b22; border: 1px solid #30363d; padding: 15px; border-radius: 5px; }
    h1, h2, h3 { color: #00ff41 !important; font-family: 'Courier New', monospace; }
    div[data-testid="stMetricValue"] { color: #ff4b4b; }
    .stExpander { border: 1px solid #30363d; border-radius: 5px; }
    div[data-testid="stLinkButton"] > a {
        background-color: #1f77b4; color: white; border: none; padding: 5px 10px; text-decoration: none; border-radius: 4px;
    }
    </style>
    """, unsafe_allow_html=True)

# --- Init DB ---
init_db()

# --- Auto-Refresh Logic (15 Mins) ---
if 'last_run' not in st.session_state:
    st.session_state['last_run'] = time.time()

# --- Sidebar ---
with st.sidebar:
    st.header("⚙️ OPERATIONS")
    api_key = st.text_input("Google API Key", type="password")
    
    # Manual Trigger
    if st.button("🔄 FORCE SCAN"):
        if api_key:
            with st.spinner("Scanning Sources..."):
                collector = DataCollector()
                status = asyncio.run(collector.run_collection_cycle(api_key))
                st.session_state['last_run'] = time.time()
            st.success(status)
            st.rerun()
        else:
            st.error("Enter API Key")

    st.markdown("---")
    st.markdown("**Auto-Update:** System scans every 15 min.")
    
    filter_mode = st.radio("Threat Filter", ["All Traffic", "Israel Watch 🇮🇱", "Critical/Zero-Day"])

# --- Background Auto-Runner Hook ---
# Checks if 15 mins (900 sec) passed since last run
current_time = time.time()
if (current_time - st.session_state['last_run'] > 900) and api_key:
    collector = DataCollector()
    asyncio.run(collector.run_collection_cycle(api_key))
    st.session_state['last_run'] = current_time
    st.toast("System Auto-Updated Sources", icon="🔄")
    st.rerun()

# --- Load Data ---
df = get_all_intel()

# --- Filter ---
if not df.empty:
    if filter_mode == "Israel Watch 🇮🇱":
        df = df[df['victim_target'] == 'IL']
    elif filter_mode == "Critical/Zero-Day":
        df = df[(df['is_zero_day'] == 1) | (df['status'] == 'Active')]

# --- Metrics ---
c1, c2, c3, c4 = st.columns(4)
c1.metric("Live Threats (24h)", len(df))
c2.metric("Zero Days", len(df[df['is_zero_day'] == 1]) if not df.empty else 0)
c3.metric("IL Targeted", len(df[df['victim_target'] == 'IL']) if not df.empty else 0)
c4.metric("Defcon", "3" if len(df) < 10 else "1")

# --- Map (Fixed) ---
st.subheader("🌍 LIVE ATTACK MAP")
if not df.empty:
    map_data = []
    for _, row in df.iterrows():
        # Force default coordinates if missing so lines always draw
        src_code = row['attacker_origin'] if row['attacker_origin'] else "XX"
        dst_code = row['victim_target'] if row['victim_target'] else "Global"
        
        src = get_coords(src_code)
        dst = get_coords(dst_code)
        
        map_data.append({
            "source": src,
            "target": dst,
            "actor": row['threat_actor'],
            "title": row['title']
        })

    layer = pdk.Layer(
        "ArcLayer",
        data=map_data,
        get_source_position="source",
        get_target_position="target",
        get_width=2,
        get_tilt=15,
        get_source_color=[255, 0, 0, 200],
        get_target_color=[0, 255, 0, 200],
    )
    view_state = pdk.ViewState(latitude=30, longitude=10, zoom=1.2, pitch=40)
    st.pydeck_chart(pdk.Deck(layers=[layer], initial_view_state=view_state, tooltip={"text": "{actor}\n{title}"}))
else:
    st.info("System initializing... Waiting for data.")

# --- Feed (Fixed Titles) ---
col1, col2 = st.columns([1, 2])

with col1:
    st.subheader("📊 VECTORS")
    if not df.empty:
        fig = px.pie(df, names='attack_vector', hole=0.6, template="plotly_dark")
        fig.update_traces(textinfo='label+percent')
        st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("📟 INTELLIGENCE FEED")
    if not df.empty:
        for _, row in df.iterrows():
            color = "red" if row['victim_target'] == 'IL' else "green"
            # TITLE IS NOW THE ARTICLE TITLE (Specific)
            label = f"[{row['timestamp'][11:16]}] {row['title']}"
            
            with st.expander(label):
                c_a, c_b = st.columns(2)
                with c_a:
                    st.markdown(f"**Actor:** {row['threat_actor']}")
                    st.markdown(f"**Origin:** {row['attacker_origin']}")
                with c_b:
                    st.markdown(f"**Target:** {row['victim_target']}")
                    st.markdown(f"**Vector:** {row['attack_vector']}")
                
                st.markdown("---")
                st.markdown(f"**Summary:** :{color}[{row['summary']}]")
                
                if row['source_url'] and row['source_url'] != '#':
                    st.link_button("🔗 Read Full Report", row['source_url'])
    else:
        st.write("No active threats detected in the last 24h.")
