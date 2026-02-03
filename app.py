import streamlit as st
import pandas as pd
import pydeck as pdk
import plotly.express as px
import asyncio
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
    </style>
    """, unsafe_allow_html=True)

# --- Init ---
init_db()

# --- Sidebar ---
with st.sidebar:
    st.header("⚙️ SYSTEM CONTROLS")
    api_key = st.text_input("Google API Key", type="password")
    
    if st.button("🔄 INITIATE SCAN"):
        if api_key:
            with st.spinner("Collecting Intel..."):
                collector = DataCollector()
                status = asyncio.run(collector.run_collection_cycle(api_key))
            st.success(status)
            st.rerun()
        else:
            st.error("API Key Required!")

    st.divider()
    filter_mode = st.radio("Threat Filter", ["All Traffic", "Israel Watch 🇮🇱", "Critical/Zero-Day"])

# --- Data Loading ---
df = get_all_intel()

# --- Filter Logic ---
if not df.empty:
    if filter_mode == "Israel Watch 🇮🇱":
        df = df[df['victim_target'] == 'IL']
    elif filter_mode == "Critical/Zero-Day":
        df = df[(df['is_zero_day'] == 1) | (df['status'] == 'Active')]

# --- Metrics ---
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Threats", len(df))
c2.metric("Zero Days", len(df[df['is_zero_day'] == 1]) if not df.empty else 0)
c3.metric("High Severity", len(df[df['attack_vector'].str.contains('Ransomware|Exploit', case=False, na=False)]) if not df.empty else 0)
c4.metric("Defcon", "3" if len(df) < 10 else "1")

# --- Map ---
st.subheader("🌍 LIVE ATTACK MAP")
if not df.empty:
    map_data = []
    for _, row in df.iterrows():
        src = get_coords(row['attacker_origin'])
        dst = get_coords(row['victim_target'])
        if src != [0,0] and dst != [0,0]:
            map_data.append({"source": src, "target": dst, "actor": row['threat_actor']})

    layer = pdk.Layer(
        "ArcLayer",
        data=map_data,
        get_source_position="source",
        get_target_position="target",
        get_width=3,
        get_tilt=15,
        get_source_color=[255, 0, 0, 180],
        get_target_color=[0, 255, 65, 180],
    )
    view_state = pdk.ViewState(latitude=20, longitude=0, zoom=1.5, pitch=45)
    st.pydeck_chart(pdk.Deck(layers=[layer], initial_view_state=view_state, map_style=None))
else:
    st.info("Awaiting Intelligence Data...")

# --- Feed ---
col1, col2 = st.columns([1, 2])

with col1:
    st.subheader("📊 ATTACK VECTORS")
    if not df.empty:
        fig = px.pie(df, names='attack_vector', hole=0.5, template="plotly_dark")
        fig.update_traces(textposition='inside', textinfo='percent+label')
        st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("📟 INTELLIGENCE FEED")
    if not df.empty:
        for _, row in df.iterrows():
            color = "red" if row['victim_target'] == 'IL' else "green"
            flag = "🇮🇱" if row['victim_target'] == 'IL' else ""
            
            with st.expander(f"[{row['timestamp'][11:16]}] {row['threat_actor']} ➡️ {row['victim_target']} {flag}"):
                c_a, c_b = st.columns(2)
                with c_a:
                    st.markdown(f"**Origin:** {row['attacker_origin']}")
                    st.markdown(f"**Vector:** {row['attack_vector']}")
                with c_b:
                    st.markdown(f"**Status:** {row['status']}")
                    if row['cve_id'] != 'N/A':
                        st.markdown(f"**CVE:** `{row['cve_id']}`")
                
                st.markdown(f"**Summary:** :{color}[{row['summary']}]")
                
                # LINK BUTTON
                if row['source_url'] and row['source_url'] != '#':
                    st.link_button("🔗 Read Full Report", row['source_url'])
    else:
        st.write("System Offline.")
