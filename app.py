import streamlit as st
import asyncio
import pandas as pd
import sqlite3
import datetime
import pytz
import time
import re
import streamlit.components.v1 as components
from utils import *
from dateutil import parser as date_parser
from streamlit_autorefresh import st_autorefresh

# --- CONFIGURATION ---
st.set_page_config(page_title="CTI WAR ROOM", layout="wide", page_icon="🛡️")

# --- CSS STYLING ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Rubik:wght@300;400;600&family=Heebo:wght@300;400;700&display=swap');
    
    .stApp { direction: rtl; text-align: right; background-color: #0b0f19; font-family: 'Heebo', sans-serif; }
    h1, h2, h3, h4, h5, h6, p, div, span, label, .stMarkdown { text-align: right; font-family: 'Heebo', sans-serif; }
    
    /* Move Sidebar Toggle to Left (RTL Fix) */
    [data-testid="stSidebarCollapseButton"] {
        float: left;
        margin-left: 10px;
        margin-right: auto;
    }
    
    /* Widget Alignments */
    .stTextInput input, .stSelectbox, .stMultiSelect { direction: rtl; text-align: right; }
    .stButton button { width: 100%; font-family: 'Rubik', sans-serif; border-radius: 8px; }
    .stTabs [data-baseweb="tab-list"] { justify-content: flex-end; gap: 15px; }
    
    /* Tool Cards */
    .tool-card {
        background: rgba(30, 41, 59, 0.7);
        border: 1px solid rgba(56, 189, 248, 0.3);
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        margin-bottom: 15px;
        height: 100%;
        color: white;
        cursor: pointer;
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    }
    .tool-card:hover {
        background: rgba(56, 189, 248, 0.2);
        border-color: #38bdf8;
        transform: translateY(-4px);
        box-shadow: 0 10px 15px -3px rgba(56, 189, 248, 0.2), 0 4px 6px -2px rgba(56, 189, 248, 0.1);
    }
    .tool-icon { font-size: 32px; margin-bottom: 10px; display: block; filter: drop-shadow(0 0 5px rgba(255,255,255,0.3)); }
    .tool-name { font-weight: 700; color: #f1f5f9; display: block; margin-bottom: 5px; font-size: 1.1rem; }
    .tool-desc { font-size: 0.85rem; color: #cbd5e1; display: block; line-height: 1.4; }
    a { text-decoration: none; }

    /* Report Cards */
    .report-card {
        background: rgba(30, 41, 59, 0.4); backdrop-filter: blur(12px);
        border: 1px solid rgba(148, 163, 184, 0.1); border-radius: 12px; padding: 24px; margin-bottom: 20px;
    }

    /* IOC Score Cards */
    .ioc-card {
        padding: 15px; border-radius: 10px; text-align: center; color: white; margin-bottom: 10px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .ioc-safe { background: linear-gradient(135deg, #10b981, #059669); }
    .ioc-danger { background: linear-gradient(135deg, #ef4444, #b91c1c); }
    .ioc-neutral { background: linear-gradient(135deg, #64748b, #475569); }
    .ioc-title { font-size: 0.9rem; font-weight: bold; opacity: 0.9; }
    .ioc-value { font-size: 1.8rem; font-weight: bold; margin: 5px 0; }
    .ioc-sub { font-size: 0.8rem; opacity: 0.8; }
    
    /* Redirect Alert */
    .redirect-alert {
        background: rgba(245, 158, 11, 0.2); border: 1px solid #f59e0b; color: #fcd34d;
        padding: 15px; border-radius: 8px; margin-bottom: 15px;
        display: flex; align-items: center; gap: 10px; font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

def clean_html(raw_html):
    cleanr = re.compile('<.*?>')
    return re.sub(cleanr, '', str(raw_html)).replace('"', '&quot;').strip()

def get_feed_card_html(row, date_str):
    sev = row['severity'].lower()
    badge_bg, badge_color, border_color = "rgba(100, 116, 139, 0.2)", "#cbd5e1", "rgba(100, 116, 139, 0.3)"
    
    if "critical" in sev or "high" in sev:
        badge_bg, badge_color, border_color = "rgba(220, 38, 38, 0.2)", "#fca5a5", "#ef4444"
    elif "medium" in sev:
        badge_bg, badge_color, border_color = "rgba(59, 130, 246, 0.2)", "#93c5fd", "#3b82f6"
        
    source_display = f"🇮🇱 {row['source']}" if row['source'] == 'INCD' else f"📡 {row['source']}"
    tag_display = row.get('tags', 'כללי')
    summary = clean_html(row['summary']).replace('\n', '<br>')
    
    return f"""
    <div class="report-card" style="direction: rtl; text-align: right; border-right: 4px solid {border_color};">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; flex-direction: row-reverse;">
             <div style="display: flex; gap: 10px;">
                <div style="background: {badge_bg}; color: {badge_color}; border: 1px solid {border_color}; padding: 2px 10px; border-radius: 99px; font-size: 0.75rem; font-weight: bold;">
                    {row['severity'].upper()}
                </div>
                <div style="background: rgba(30, 41, 59, 0.5); color: #94a3b8; border: 1px solid #334155; padding: 2px 10px; border-radius: 99px; font-size: 0.75rem;">
                    {tag_display}
                </div>
             </div>
            <div style="font-family: 'Rubik'; font-size: 0.85rem; color: #94a3b8;">
                {date_str} • <b style="color: #e2e8f0;">{source_display}</b>
            </div>
        </div>
        <div style="font-size: 1.25rem; font-weight: 700; color: #f1f5f9; margin-bottom: 12px;">{row['title']}</div>
        <div style="font-size: 0.95rem; color: #cbd5e1; margin-bottom: 15px; opacity: 0.9; line-height: 1.6;">{summary}</div>
        <div style="text-align: left;">
            <a href="{row['url']}" target="_blank" style="display: inline-flex; align-items: center; gap: 5px; color: #38bdf8; text-decoration: none; font-size: 0.85rem; padding: 5px 10px; background: rgba(56, 189, 248, 0.1); border-radius: 6px;">
                פתח מקור 🔗
            </a>
        </div>
    </div>
    """

# --- INITIALIZATION ---
init_db() 
IL_TZ = pytz.timezone('Asia/Jerusalem')
st_autorefresh(interval=15 * 60 * 1000, key="data_refresh")

GROQ_KEY = st.secrets.get("groq_key", "")
VT_KEY = st.secrets.get("vt_key", "")
URLSCAN_KEY = st.secrets.get("urlscan_key", "")
ABUSE_KEY = st.secrets.get("abuseipdb_key", "")

# --- CORE UPDATE FUNCTIONS ---
async def update_live_feed(p_bar, status_text):
    status_text.info("📡 אוסף ידיעות חמות מהמקורות...")
    col, proc = CTICollector(), AIBatchProcessor(GROQ_KEY)
    raw = await col.get_all_data()
    p_bar.progress(30)
    
    # Filter EXISTING items to save AI time (but keep quality high)
    existing = get_existing_urls()
    raw_to_process = [r for r in raw if r['url'] not in existing]
    
    if raw_to_process:
        status_text.info(f"🤖 מנתח {len(raw_to_process)} ידיעות חדשות (AI Processing)...")
        analyzed = await proc.analyze_batch(raw_to_process)
        save_reports(raw_to_process, analyzed)
    p_bar.progress(60)

async def update_threat_dossiers(p_bar, status_text):
    status_text.info("🕵️ מעדכן תיקי שחקני איום (Deep Scan)...")
    threats = APTSheetCollector().fetch_threats()
    scanner, proc = DeepWebScanner(), AIBatchProcessor(GROQ_KEY)
    for i, threat in enumerate(threats):
        res = scanner.scan_actor(threat['name'], limit=2)
        if res:
             # Same filtering logic
             existing = get_existing_urls()
             res_to_process = [r for r in res if r['url'] not in existing]
             if res_to_process:
                 analyzed = await proc.analyze_batch(res_to_process)
                 save_reports(res_to_process, analyzed)
