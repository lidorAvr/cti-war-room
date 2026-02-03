import streamlit as st
import pandas as pd
import pydeck as pdk
import plotly.express as px
import asyncio
from utils import init_db, DataCollector, get_all_intel, get_coords

# --- Config & Styling ---
st.set_page_config(page_title="CTI WAR ROOM", page_icon="🛡️", layout="wide")

# Custom CSS for Cyberpunk Aesthetic
st.markdown("""
    <style>
    .stApp {
        background-color: #0e1117;
        color: #00ff41;
    }
    .metric-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        padding: 15px;
        border-radius: 5px;
        color: #00ff41;
    }
    h1, h2, h3 {
        color: #00ff41 !important; 
        font-family: 'Courier New', monospace;
    }
    div[data-testid="stMetricValue"] {
        color: #ff4b4b;
    }
    </style>
    """, unsafe_allow_html=True)

# --- Init ---
init_db()

# --- Sidebar Controls ---
with st.sidebar:
    st.header("⚙️ SYSTEM CONTROLS")
    
    # Secret Management for Streamlit Cloud
    api_key = st.secrets.get("GOOGLE_API_KEY", None)
    if not api_key:
        api_key = st.text_input("Enter Google API Key", type="password")
    
    if st.button("🔄 INITIATE SCAN"):
        if api_key:
            with st.spinner("Scanning Tier-1 Feeds & Analyzing with Gemini AI..."):
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
if filter_mode == "Israel Watch 🇮🇱":
    df = df[df['victim_target'] == 'IL']
elif filter_mode == "Critical/Zero-Day":
    df = df[(df['is_zero_day'] == 1) | (df['status'] == 'Active')]

# --- Top Bar Metrics ---
c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Threats", len(df))
c2.metric("Zero Days", len(df[df['is_zero_day'] == 1]))
c3.metric("Active Campaigns", len(df[df['is_campaign'] == 1]))
c4.metric("Defcon Level", "3" if len(df) < 10 else "1")

# --- 3D Globe Visualization ---
st.subheader("🌍 LIVE ATTACK MAP")

if not df.empty:
    # Prepare Map Data
    map_data = []
    for _, row in df.iterrows():
        src = get_coords(row['attacker_origin'])
        dst = get_coords(row['victim_target'])
        if src != [0,0] and dst != [0,0]:
            map_data.append({
                "source": src,
                "target": dst,
                "actor": row['threat_actor']
            })

    # PyDeck Layer
    layer = pdk.Layer(
        "ArcLayer",
        data=map_data,
        get_source_position="source",
        get_target_position="target",
        get_width=3,
        get_tilt=15,
        get_source_color=[255, 0, 0, 180],  # Red for attacker
        get_target_color=[0, 255, 65, 180], # Green for victim
    )

    view_state = pdk.ViewState(latitude=20, longitude=0, zoom=1.5, pitch=45)
    st.pydeck_chart(pdk.Deck(layers=[layer], initial_view_state=view_state, map_style=None))
else:
    st.info("No data available. Initiate Scan.")

# --- Analytics & Feed ---
col1, col2 = st.columns([1, 2])

with col1:
    st.subheader("📊 ATTACK VECTORS")
    if not df.empty:
        fig = px.pie(df, names='attack_vector', hole=0.5, template="plotly_dark")
        fig.update_traces(textposition='inside', textinfo='percent+label')
        st.plotly_chart(fig, use_container_width=True)

with col2:
    st.subheader("📟 INTELLIGENCE FEED")
    for _, row in df.iterrows():
        color = "red" if row['victim_target'] == 'IL' else "green"
        with st.expander(f"[{row['timestamp'][:10]}] {row['threat_actor']} -> {row['victim_target']}"):
            st.markdown(f"**Origin:** {row['attacker_origin']} | **Vector:** {row['attack_vector']}")
            st.markdown(f"**Summary:** :{color}[{row['summary']}]")
            if row['is_zero_day']:
                st.error("⚠️ ZERO DAY DETECTED")