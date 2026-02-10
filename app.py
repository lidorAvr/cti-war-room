import sqlite3
import asyncio
import aiohttp
import json
import datetime
import requests
import pandas as pd
import re
import ipaddress
import pytz
import feedparser
import base64
import time
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from dateutil import parser as date_parser
from ddgs import DDGS
import google.generativeai as genai
import streamlit as st

DB_NAME = "cti_dashboard.db"
IL_TZ = pytz.timezone('Asia/Jerusalem')

# --- HTTP HEADERS ---
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7'
}

# --- DATE HELPER ---
def parse_flexible_date(date_obj):
    """
    Robust date parser that handles RSS struct_time, strings, and NaTs.
    Returns ISO format string in Israel Time.
    """
    now = datetime.datetime.now(IL_TZ)
    try:
        if isinstance(date_obj, time.struct_time):
            dt = datetime.datetime(*date_obj[:6], tzinfo=pytz.utc)
            return dt.astimezone(IL_TZ).isoformat()
        
        if isinstance(date_obj, str):
            dt = date_parser.parse(date_obj)
            if dt.tzinfo is None:
                dt = pytz.utc.localize(dt)
            return dt.astimezone(IL_TZ).isoformat()
            
        if isinstance(date_obj, datetime.datetime):
            if date_obj.tzinfo is None:
                date_obj = pytz.utc.localize(date_obj)
            return date_obj.astimezone(IL_TZ).isoformat()
    except:
        pass
    return now.isoformat()

# --- IOC VALIDATION ---
def identify_ioc_type(ioc):
    ioc = ioc.strip()
    if re.match(r'^https?://', ioc) or re.match(r'^www\.', ioc):
        return "url"
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass
    if re.match(r'^[a-fA-F0-9]{32}$', ioc) or re.match(r'^[a-fA-F0-9]{40}$', ioc) or re.match(r'^[a-fA-F0-9]{64}$', ioc):
        return "hash"
    if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', ioc):
        return "domain"
    return None

# --- DATABASE MANAGEMENT ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS intel_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        published_at TEXT,
        source TEXT,
        url TEXT UNIQUE,
        title TEXT,
        category TEXT,
        severity TEXT,
        summary TEXT,
        actor_tag TEXT,
        tags TEXT
    )''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_url ON intel_reports(url)")
    limit_regular = (datetime.datetime.now(IL_TZ) - datetime.timedelta(days=3)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE source NOT IN ('INCD', 'DeepWeb') AND published_at < ?", (limit_regular,))
    conn.commit()
    conn.close()

def _is_url_processed(url):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT id FROM intel_reports WHERE url = ?", (url,))
        result = c.fetchone()
        conn.close()
        return result is not None
    except: return False

def get_existing_urls():
    """Returns a set of all URLs in DB for fast lookup."""
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT url FROM intel_reports")
        urls = {row[0] for row in c.fetchall()}
        conn.close()
        return urls
    except: return set()

# --- DEEP WEB SCANNER ---
class DeepWebScanner:
    def scan_actor(self, actor_name, limit=3):
        results = []
        try:
            query = f'"{actor_name}" cyber threat intelligence malware analysis report'
            with DDGS() as ddgs:
                ddg_results = list(ddgs.text(query, max_results=limit))
                for res in ddg_results:
                    url = res.get('href')
                    if _is_url_processed(url): continue
                    
                    results.append({
                        "title": res.get('title'),
                        "url": url,
                        "date": datetime.datetime.now(IL_TZ).isoformat(),
                        "source": "DeepWeb",
                        "summary": res.get('body', 'No summary available.'),
                        "actor_tag": actor_name
                    })
        except Exception as e:
            print(f"Deep Scan Error: {e}")
        return results

# --- CONNECTION & AI ENGINES ---
class ConnectionManager:
    @staticmethod
    def check_groq(key):
        if not key: return False, "Missing Key"
        if key.startswith("gsk_"): return True, "Connected"
        return False, "Invalid Format"

async def query_groq_api(api_key, prompt, model="llama-3.3-70b-versatile", json_mode=True):
    if not api_key: return "Error: Missing API Key"
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    
    models = [model, "llama-3.1-8b-instant"]
    
    for m in models:
        payload = {"model": m, "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
        if json_mode: payload["response_format"] = {"type": "json_object"}
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(url, json=payload, headers=headers, timeout=45) as resp:
                    if resp.status == 429:
                        time.sleep(1)
                        continue
                    if resp.status == 200:
                        data = await resp.json()
                        return data['choices'][0]['message']['content']
            except: continue
                
    return None

def translate_with_gemini_hebrew(text_content):
    """
    Enforces Hebrew translation via Gemini - ORIGINAL HIGH QUALITY PROMPT
    """
    try:
        gemini_key = st.secrets.get("gemini_key")
        if not gemini_key: return text_content
        
        genai.configure(api_key=gemini_key)
        model = genai.GenerativeModel('gemini-pro')
        
        # --- RESTORED ORIGINAL PROMPT ---
        prompt = f"""
        Act as a Cyber Intelligence Editor.
        Task: Rewrite the following text into professional Hebrew.
        Rules:
        1. Keep technical terms (CVE, Malware, Exploit) in English.
        2. If the text is a long Telegram message, summarize it into 3 bullet points.
        3. Tone: Operational, Concise.
        
        Input:
        {text_content}
        """
        response = model.generate_content(prompt)
        return response.text
    except:
        return text_content

class AIBatchProcessor:
    def __init__(self, key):
        self.key = key
    
    def _determine_tag_severity(self, text, source):
        text = text.lower()
        sev = "Medium"
        tag = "כללי"
        
        # Severity Logic
        if any(x in text for x in ['exploited', 'zero-day', 'ransomware', 'critical', 'cve-202', 'apt']):
            sev = "High"
        
        # Tag Logic
        if source == "INCD" or "israel" in text or "iran" in text: tag = "ישראל"
        elif "cve-" in text or "patch" in text or "vulnerability" in text: tag = "פגיעויות"
        elif "phishing" in text or "credential" in text: tag = "פיישינג"
        elif "malware" in text or "trojan" in text or "backdoor" in text: tag = "נוזקה"
        elif "research" in text or "analysis" in text: tag = "מחקר"
        
        return tag, sev

    async def analyze_batch(self, items):
        if not items: return []
        
        # --- Speed Optimization: Filter existing items BEFORE AI ---
        existing = get_existing_urls()
        items_to_process = [i for i in items if i['url'] not in existing]
        if not items_to_process: return []

        chunk_size = 3 
        results = []
        
        # --- RESTORED ORIGINAL PROMPT ---
        system_instruction = """
        You are an Elite Cyber News Editor.
        Task: Create a structured summary for a dashboard.
        
        For each item:
        1. **Title**: Professional Hebrew title.
        2. **Summary**: A concise Hebrew summary (Maximum 3 sentences or bullet points). 
           - IF TEXT IS LONG (like Telegram): Summarize the "Bottom Line".
           - Keep technical terms in English.
        
        Output JSON: {"items": [{"id": 0, "title": "Hebrew Title", "summary": "Hebrew Summary"}]}
        """
        
        for i in range(0, len(items_to_process), chunk_size):
            chunk = items_to_process[i:i+chunk_size]
            batch_lines = [f"ID:{idx} | Text:{x['title']} - {x['summary'][:2000]}" for idx, x in enumerate(chunk)]
            batch_text = "\n".join(batch_lines)
            prompt = f"{system_instruction}\nData:\n{batch_text}"
            
            # 1. Groq Analysis
            res = await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=True)
            
            chunk_map = {}
            if res:
                try:
                    data = json.loads(res)
                    for item in data.get("items", []): chunk_map[item.get('id')] = item
                except: pass
            
            for j in range(len(chunk)):
                ai = chunk_map.get(j, {})
                
                # 2. Heuristic Tagging
                raw_txt = (chunk[j]['title'] + chunk[j]['summary'])
                final_tag, final_sev = self._determine_tag_severity(raw_txt, chunk[j]['source'])
                
                # 3. Gemini Polish (Translation & Summary Enforcement)
                draft_title = ai.get('title', chunk[j]['title'])
                draft_sum = ai.get('summary', chunk[j]['summary'])
                
                heb_title = translate_with_gemini_hebrew(draft_title)
                heb_sum = translate_with_gemini_hebrew(draft_sum)

                results.append({
                    "category": "News", 
                    "severity": final_sev, 
                    "title": heb_title,
                    "summary": heb_sum,
                    "published_at": chunk[j]['date'], 
                    "actor_tag": chunk[j].get('actor_tag', None),
                    "tags": final_tag
                })
        return results

    async def analyze_single_ioc(self, ioc, ioc_type, data):
        lean_data = self._extract_key_intel(data)
        # --- RESTORED ORIGINAL PROMPT ---
        prompt = f"""
        Act as a Senior SOC Analyst (Unit 8200 style).
        Target: {ioc} ({ioc_type})
        Data: {json.dumps(lean_data)}
        
        Output Markdown (HEBREW ONLY):
        ### 🛡️ הערכה מבצעית
        * **פסק דין**: [זדוני/חשוד/נקי]
        * **רמת ביטחון**: [גבוהה/בינונית]
        * **ניתוח**: 2-3 sentences analyzing the findings.
        
        ### 🏢 המלצות לפעולה
        * **חסימה**: Firewall/Proxy rules.
        * **ציד**: What to look for in EDR.
        """
        res = await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)
        return res if res else "שגיאה בניתוח AI. נסה שנית."

    def _extract_key_intel(self, raw_data):
        summary = {}
        if 'virustotal' in raw_data and raw_data['virustotal']:
            vt = raw_data['virustotal']
            summary['virustotal'] = {
                'malicious_votes': vt.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0),
                'tags': vt.get('attributes', {}).get('tags', [])
            }
        return summary

    async def generate_hunting_queries(self, actor):
        prompt = f"Generate XQL & YARA hunting rules for actor: {actor['name']}. Tools: {actor.get('tools')}."
        return await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)

class ThreatLookup:
    def __init__(self, vt_key=None, urlscan_key=None, abuse_key=None):
        self.vt_key, self.urlscan_key, self.abuse_key = vt_key, urlscan_key, abuse_key

    def query_virustotal(self, ioc, ioc_type):
        if not self.vt_key: return None
        try:
            if ioc_type == "url":
                url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
                endpoint = f"urls/{url_id}"
            else:
                endpoint = f"{'ip_addresses' if ioc_type == 'ip' else 'domains' if ioc_type == 'domain' else 'files'}/{ioc}"
            
            res = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}", headers={"x-apikey": self.vt_key}, timeout=10)
            return res.json().get('data', {}) if res.status_code == 200 else None
        except: return None

    def query_urlscan(self, ioc):
        if not self.urlscan_key: return None
        try:
            search_query = f'"{ioc}"'
            res = requests.get(f"https://urlscan.io/api/v1/search/?q={search_query}", headers={"API-Key": self.urlscan_key}, timeout=10)
            data = res.json()
            if data.get('results'):
                scan_id = data['results'][0]['_id']
                full_res = requests.get(f"https://urlscan.io/api/v1/result/{scan_id}/", headers={"API-Key": self.urlscan_key}, timeout=10)
                return full_res.json() if full_res.status_code == 200 else None
            return None
        except: return None

    def query_abuseipdb(self, ip):
        if not self.abuse_key: return None
        try:
            res = requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': self.abuse_key, 'Accept': 'application/json'}, params={'ipAddress': ip, 'maxAgeInDays': 90}, timeout=10)
            return res.json().get('data', {})
        except: return None

class AnalystToolkit:
    @staticmethod
    def get_tools():
        return {
            "Analysis": [
                {"name": "CyberChef", "url": "https://gchq.github.io/CyberChef/", "desc": "פענוח", "icon": "🔪"},
                {"name": "Any.Run", "url": "https://app.any.run/", "desc": "Sandbox", "icon": "📦"},
                {"name": "UnpacMe", "url": "https://www.unpac.me/", "desc": "Unpacking", "icon": "🔓"}
            ],
            "Lookup": [
                {"name": "VirusTotal", "url": "https://www.virustotal.com/", "desc": "Scanner", "icon": "🦠"},
                {"name": "AbuseIPDB", "url": "https://www.abuseipdb.com/", "desc": "Reputation", "icon": "🚫"},
                {"name": "Talos", "url": "https://talosintelligence.com/", "desc": "Intel", "icon": "🛡️"}
            ],
            "Tools": [
                {"name": "MxToolbox", "url": "https://mxtoolbox.com/", "desc": "Network", "icon": "🔧"},
                {"name": "URLScan", "url": "https://urlscan.io/", "desc": "Web Scan", "icon": "📷"},
                {"name": "OTX", "url": "https://otx.alienvault.com/", "desc": "Open Intel", "icon": "👽"}
            ]
        }

class APTSheetCollector:
    def fetch_threats(self): 
        return [
            {
                "name": "MuddyWater", 
                "origin": "Iran (MOIS)", 
                "target": "Israel, Turkey, Jordan", 
                "type": "Espionage", 
                "tools": "PowerShell, Ligolo, ScreenConnect", 
                "keywords": ["muddywater", "static_kitten", "mercury"], 
                "desc": "קבוצת תקיפה המזוהה עם משרד המודיעין האיראני. מתמקדת בגניבת מידע ממשלתי וצבאי באמצעות פישינג וכלי RMM.", 
                "mitre": "T1059.001, T1105, T1021"
            },
            {
                "name": "OilRig (APT34)", 
                "origin": "Iran (IRGC)", 
                "target": "Israel Critical Infra", 
                "type": "Espionage", 
                "tools": "Karkoff, SideTwist, DNSpionage", 
                "keywords": ["oilrig", "apt34", "helix_kitten"], 
                "desc": "מתמקדת במגזרי פיננסים, אנרגיה ותקשורת. ידועה בשימוש ב-DNS Tunneling ובתקיפות שרשרת אספקה.", 
                "mitre": "T1071.004, T1048"
            },
            {
                "name": "Agonizing Serpens", 
                "origin": "Iran", 
                "target": "Israel (Education, Tech)", 
                "type": "Wiper / Destructive", 
                "tools": "BiBiWiper, Moneybird", 
                "keywords": ["agonizing serpens", "bibiwiper", "moneybird"], 
                "desc": "קבוצה הרסנית. מתחזה לכופרה אך מטרתה השמדת מידע. תקפה את הטכניון ואת חברת הייעוץ הכלכלי.", 
                "mitre": "T1485, T1486"
            }
        ]

class CTICollector:
    SOURCES = [
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "TheHackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        {"name": "INCD", "url": "https://www.gov.il/he/rss/news_list?officeId=4bcc13f5-fed6-4b8c-b8ee-7bf4a6bc81c8", "type": "rss"},
        {"name": "INCD", "url": "https://t.me/s/Israel_Cyber", "type": "telegram"},
        # --- NEW SOURCE: Malwarebytes ---
        {"name": "Malwarebytes", "url": "https://www.malwarebytes.com/blog/feed/", "type": "rss"}
    ]

    async def fetch_item(self, session, source):
        items = []
        try:
            async with session.get(source['url'], headers=HEADERS, timeout=25) as resp:
                if resp.status != 200: return []
                content = await resp.text()
                
                # --- RSS ---
                if source['type'] == 'rss':
                    feed = feedparser.parse(content)
                    entries = feed.entries[:10]

                    for entry in entries:
                        date_raw = getattr(entry, 'published_parsed', None) or getattr(entry, 'updated_parsed', None)
                        pub_date = parse_flexible_date(date_raw)
                        
                        items.append({"title": entry.title, "url": entry.link, "date": pub_date, "source": source['name'], "summary": BeautifulSoup(entry.summary, "html.parser").get_text()[:1500]})

                # --- JSON ---
                elif source['type'] == 'json':
                     data = json.loads(content)
                     for v in data.get('vulnerabilities', [])[:10]:
                         url = f"https://nvd.nist.gov/vuln/detail/{v['cveID']}"
                         pub_date = parse_flexible_date(v.get('dateAdded'))
                         items.append({"title": f"KEV: {v['cveID']}", "url": url, "date": pub_date, "source": "CISA", "summary": v.get('shortDescription')})
                
                # --- TELEGRAM ---
                elif source['type'] == 'telegram':
                    soup = BeautifulSoup(content, 'html.parser')
                    msgs = soup.find_all('div', class_='tgme_widget_message_wrap')
                    for msg in msgs[-10:]:
                        try:
                            text_div = msg.find('div', class_='tgme_widget_message_text')
                            if not text_div: continue
                            text = text_div.get_text(separator=' ')
                            
                            time_tag = msg.find('time')
                            date_raw = time_tag['datetime'] if time_tag else None
                            pub_date = parse_flexible_date(date_raw)
                            
                            link = msg.find('a', class_='tgme_widget_message_date')
                            url = link['href'] if link else source['url']
                            
                            items.append({"title": "התרעת מערך הסייבר", "url": url, "date": pub_date, "source": "INCD", "summary": text})
                        except: pass

        except: pass
        return items

    async def get_all_data(self):
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_item(session, s) for s in self.SOURCES]
            results = await asyncio.gather(*tasks)
            return [i for sub in results for i in sub]

def save_reports(raw, analyzed):
    conn = sqlite3.connect(DB_NAME)
    c, cnt = conn.cursor(), 0
    # Matching Logic:
    # Analyzed list only contains items that were processed (new items).
    # We must match them back to save them.
    # Since we filter before processing, 'analyzed' corresponds to 'raw_filtered'.
    # We will assume 'raw' passed here is the FILTERED list from app.py
    
    for i, item in enumerate(raw):
        if i < len(analyzed):
            a = analyzed[i]
            try:
                c.execute("INSERT OR IGNORE INTO intel_reports (timestamp,published_at,source,url,title,category,severity,summary,actor_tag,tags) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (datetime.datetime.now(IL_TZ).isoformat(), item['date'], item['source'], item['url'], a['title'], a['category'], a['severity'], a['summary'], a.get('actor_tag'), a.get('tags')))
                if c.rowcount > 0: cnt += 1
            except: pass
    conn.commit()
    conn.close()
    return cntimport streamlit as st
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

async def perform_update():
    col, proc = CTICollector(), AIBatchProcessor(GROQ_KEY)
    raw = await col.get_all_data()
    # Speed Fix: Filter happens inside analyze_batch now to save AI time
    # We pass 'raw' but 'analyze_batch' returns only processed items.
    # To save correctly, we need to match them.
    # AIBatchProcessor.analyze_batch in utils.py now filters internally.
    if raw:
        analyzed = await proc.analyze_batch(raw)
        # We need to save only what was analyzed. 
        # But 'save_reports' expects 'raw' list to match.
        # Quick fix: Pass 'raw' but save_reports will only save if indices match? 
        # No, save_reports relies on index.
        # Better: Filter 'raw' here too so it matches what analyze_batch processed.
        existing = get_existing_urls()
        raw_to_process = [r for r in raw if r['url'] not in existing]
        
        if raw_to_process and analyzed:
             return save_reports(raw_to_process, analyzed)
    return 0

if "booted" not in st.session_state:
    st.markdown("<h3 style='text-align:center;'>🚀 טוען מערכת מודיעין...</h3>", unsafe_allow_html=True)
    p_bar = st.progress(0)
    
    # Simple & Fast Update Loop
    asyncio.run(perform_update())
    p_bar.progress(50)
    
    threats = APTSheetCollector().fetch_threats()
    scanner = DeepWebScanner()
    proc = AIBatchProcessor(GROQ_KEY)
    
    # Process Threats
    for i, threat in enumerate(threats):
        res = scanner.scan_actor(threat['name'], limit=2)
        if res:
             analyzed = asyncio.run(proc.analyze_batch(res))
             # Same filtering logic applies
             existing = get_existing_urls()
             res_to_process = [r for r in res if r['url'] not in existing]
             if res_to_process and analyzed:
                 save_reports(res_to_process, analyzed)
        p_bar.progress(50 + int((i+1)/len(threats) * 50))
        
    st.session_state['booted'] = True
    st.rerun()

# --- SIDEBAR ---
with st.sidebar:
    st.image("https://cdn-icons-png.flaticon.com/512/9203/9203726.png", width=60)
    st.markdown("### CTI WAR ROOM")
    ok, msg = ConnectionManager.check_groq(GROQ_KEY)
    st.caption(f"AI STATUS: {msg}")
    if st.button("⚡ סנכרון ידני"):
        count = asyncio.run(perform_update())
        st.success(f"עודכן: {count}")
        time.sleep(1)
        st.rerun()

st.title("לוח בקרה מבצעי")
conn = sqlite3.connect(DB_NAME)
c = conn.cursor()
c.execute("SELECT COUNT(*) FROM intel_reports WHERE published_at > datetime('now', '-24 hours') AND source != 'DeepWeb'")
try:
    count_24h = c.fetchone()[0]
except: count_24h = 0

c.execute("SELECT COUNT(*) FROM intel_reports WHERE severity LIKE '%Critical%' AND published_at > datetime('now', '-24 hours')")
try:
    count_crit = c.fetchone()[0]
except: count_crit = 0
conn.close()

m4, m3, m2, m1 = st.columns(4)
m1.metric("ידיעות (24ש)", count_24h)
m2.metric("התרעות קריטיות", count_crit)
m3.metric("מקורות", "7")
m4.metric("זמינות", "100%")

st.markdown("---")

tab_feed, tab_strat, tab_tools, tab_map = st.tabs(["🔴 עדכונים שוטפים", "🗂️ תיקי תקיפה", "🛠️ מעבדת חקירות", "🌍 מפת תקיפות"])

# --- TAB 1: LIVE FEED ---
with tab_feed:
    conn = sqlite3.connect(DB_NAME)
    df_incd = pd.read_sql_query("SELECT * FROM intel_reports WHERE source = 'INCD' ORDER BY published_at DESC LIMIT 10", conn)
    df_rest = pd.read_sql_query("SELECT * FROM intel_reports WHERE source != 'INCD' AND source != 'DeepWeb' AND published_at > datetime('now', '-2 days') ORDER BY published_at DESC LIMIT 50", conn)
    conn.close()
    
    df = pd.concat([df_incd, df_rest])
    # Handle potentially empty dataframe
    if not df.empty:
        df['published_at'] = pd.to_datetime(df['published_at'], errors='coerce')
        df = df.sort_values(by='published_at', ascending=False).drop_duplicates(subset=['url'])
        
        c1, c2 = st.columns(2)
        with c1: 
            all_tags = ['הכל', 'פיישינג', 'נוזקה', 'פגיעויות', 'ישראל', 'מחקר', 'כללי']
            f_tag = st.radio("סינון לפי תגיות", all_tags, horizontal=True)
        with c2: 
            f_sev = st.radio("חומרה", ["הכל", "קריטי/גבוה", "בינוני", "נמוך/מידע"], horizontal=True)
        
        if f_tag != 'הכל': df = df[df['tags'] == f_tag]
        if "גבוה" in f_sev: df = df[df['severity'].str.contains('Critical|High', case=False)]
        
        for _, row in df.iterrows():
            try:
                dt = row['published_at']
                if pd.isnull(dt): date_display = "תאריך לא ידוע"
                else:
                    if dt.tzinfo is None: dt = pytz.utc.localize(dt).astimezone(IL_TZ)
                    else: dt = dt.astimezone(IL_TZ)
                    date_display = dt.strftime('%d/%m %H:%M')
            except: date_display = "--/--"
            
            st.markdown(get_feed_card_html(row, date_display), unsafe_allow_html=True)
    else:
        st.info("אין נתונים להצגה כרגע. המערכת אוספת מידע...")

# --- TAB 2: DOSSIER ---
with tab_strat:
    threats = APTSheetCollector().fetch_threats()
    sel = st.selectbox("בחר קבוצה", [t['name'] for t in threats])
    actor = next(t for t in threats if t['name'] == sel)
    
    st.markdown(f"""
    <div style="background:linear-gradient(180deg, rgba(30, 41, 59, 0.6) 0%, rgba(15, 23, 42, 0.8) 100%); padding:20px; border-radius:10px; border-left:4px solid #f59e0b; direction:rtl; text-align:right;">
        <h2 style="color:white; margin:0;">{actor['name']}</h2>
        <p style="color:#cbd5e1; font-size:1.1rem;">{actor['desc']}</p>
        <div style="display:flex; gap:10px; margin-top:10px;">
            <span style="background:#0f172a; padding:5px 10px; border-radius:5px; color:#fcd34d;">מוצא: {actor['origin']}</span>
            <span style="background:#0f172a; padding:5px 10px; border-radius:5px; color:#fbcfe8;">יעד: {actor['target']}</span>
            <span style="background:#0f172a; padding:5px 10px; border-radius:5px; color:#93c5fd;">סוג: {actor['type']}</span>
        </div>
        <hr style="border-color:#334155;">
        <p><b>כלים:</b> <code style="color:#fca5a5;">{actor['tools']}</code></p>
    </div>
    """, unsafe_allow_html=True)
    
    conn = sqlite3.connect(DB_NAME)
    df_deep = pd.read_sql_query(f"SELECT * FROM intel_reports WHERE source = 'DeepWeb' AND actor_tag = '{actor['name']}' ORDER BY published_at DESC LIMIT 10", conn)
    conn.close()
    
    st.markdown("##### 🕵️ ממצאי Deep Scan (אוטומטי)")
    if not df_deep.empty:
        for _, row in df_deep.iterrows():
            st.markdown(get_feed_card_html(row, "Deep Web Hit"), unsafe_allow_html=True)
    else:
        st.info("לא נמצאו ממצאים חדשים בסריקה האחרונה.")

# --- TAB 3: TOOLS & LAB ---
with tab_tools:
    st.markdown("#### 🛠️ ארגז כלים")
    toolkit = AnalystToolkit.get_tools()
    
    c1, c2, c3 = st.columns(3)
    cols = [c1, c2, c3]
    for i, (category, tools) in enumerate(toolkit.items()):
        with cols[i]:
            st.markdown(f"**{category}**")
            for tool in tools:
                st.markdown(f"""
                <a href="{tool['url']}" target="_blank">
                    <div class="tool-card">
                        <span class="tool-icon">{tool['icon']}</span>
                        <span class="tool-name">{tool['name']}</span>
                        <span class="tool-desc">{tool['desc']}</span>
                    </div>
                </a>
                """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("#### 🔬 חקירת IOC")
    
    if 'scan_res' not in st.session_state: st.session_state['scan_res'] = None
    
    ioc_in = st.text_input("הזן אינדיקטור (IP/URL/Hash)", key="ioc_input")
    if st.button("בצע חקירה"):
        st.session_state['scan_res'] = None 
        itype = identify_ioc_type(ioc_in)
        if itype:
            tl = ThreatLookup(VT_KEY, URLSCAN_KEY, ABUSE_KEY)
            with st.spinner("אוסף מודיעין ממנועים..."):
                vt = tl.query_virustotal(ioc_in, itype)
                us = tl.query_urlscan(ioc_in)
                ab = tl.query_abuseipdb(ioc_in) if itype == 'ip' else None
                ai_res = asyncio.run(AIBatchProcessor(GROQ_KEY).analyze_single_ioc(ioc_in, itype, {'virustotal': vt, 'urlscan': us}))
                
                st.session_state['scan_res'] = {'vt': vt, 'us': us, 'ab': ab, 'ai': ai_res, 'type': itype}

    # RESULTS
    res = st.session_state.get('scan_res')
    if res:
        vt, us, ab = res['vt'], res['us'], res['ab']
        
        # --- REDIRECT ALERT ---
        if us and us.get('task') and us.get('page'):
            input_url = us['task'].get('url', '')
            final_url = us['page'].get('url', '')
            if input_url != final_url:
                st.markdown(f"""
                <div class="redirect-alert">
                    ⚠️ זוהתה הפנייה (Redirect)!
                    <br>מקור: {input_url}
                    <br>יעד סופי: {final_url}
                </div>
                """, unsafe_allow_html=True)

        # 1. SCORE CARDS
        c1, c2, c3 = st.columns(3)
        
        # VT CARD
        if vt:
            mal = vt.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
            color_class = "ioc-danger" if mal > 0 else "ioc-safe"
            c1.markdown(f"""
            <div class="ioc-card {color_class}">
                <div class="ioc-title">VirusTotal</div>
                <div class="ioc-value">{mal}</div>
                <div class="ioc-sub">Malicious Hits</div>
            </div>
            """, unsafe_allow_html=True)
        else:
             c1.markdown("""<div class="ioc-card ioc-neutral"><div class="ioc-title">VirusTotal</div><div class="ioc-value">N/A</div></div>""", unsafe_allow_html=True)
        
        # ABUSEIPDB CARD
        if ab:
            score = ab.get('abuseConfidenceScore', 0)
            color_class = "ioc-danger" if score > 50 else "ioc-safe"
            c2.markdown(f"""
            <div class="ioc-card {color_class}">
                <div class="ioc-title">AbuseIPDB</div>
                <div class="ioc-value">{score}%</div>
                <div class="ioc-sub">Confidence</div>
            </div>
            """, unsafe_allow_html=True)
        elif res['type'] != 'ip':
             c2.markdown("""<div class="ioc-card ioc-neutral"><div class="ioc-title">AbuseIPDB</div><div class="ioc-value">IP Only</div></div>""", unsafe_allow_html=True)
        
        # URLSCAN CARD
        if us:
             c3.markdown("""<div class="ioc-card ioc-safe"><div class="ioc-title">URLScan</div><div class="ioc-value">Found</div><div class="ioc-sub">View Details</div></div>""", unsafe_allow_html=True)
        else:
             c3.markdown("""<div class="ioc-card ioc-neutral"><div class="ioc-title">URLScan</div><div class="ioc-value">N/A</div></div>""", unsafe_allow_html=True)

        # 2. DETAILS TABS
        t1, t2, t3, t4 = st.tabs(["🤖 ניתוח AI", "🦠 נתונים טכניים (VT)", "📷 URLScan", "🚫 AbuseIPDB"])
        
        with t1:
             st.markdown(f'<div style="direction:rtl; text-align:right;">{res["ai"]}</div>', unsafe_allow_html=True)
        
        with t2:
             if vt:
                attr = vt.get('attributes', {})
                st.write("**HTTP Response:**", attr.get('last_http_response_code'))
                st.write("**Last Analysis:**", datetime.datetime.fromtimestamp(attr.get('last_analysis_date', 0)).strftime('%Y-%m-%d'))
                st.write("**Categories:**", attr.get('categories'))
                st.write("**Tags:**", attr.get('tags'))
                st.json(attr.get('last_analysis_stats'))
             else: st.info("אין נתונים.")

        with t3:
             if us:
                task = us.get('task', {})
                page = us.get('page', {})
                st.image(task.get('screenshotURL'), caption="Screenshot")
                st.write(f"**Final URL:** {page.get('url')}")
                st.write(f"**Server:** {page.get('server')}")
                st.write(f"**Country:** {page.get('country')}")
                st.write(f"**IP:** {page.get('ip')}")
                with st.expander("Redirect Chain"):
                    st.json(us.get('data', {}).get('requests', []))
             else: st.info("אין נתונים.")

        with t4:
            if ab:
                st.write(f"**ISP:** {ab.get('isp')}")
                st.write(f"**Domain:** {ab.get('domain')}")
                st.write(f"**Usage Type:** {ab.get('usageType')}")
                st.write(f"**Country:** {ab.get('countryCode')}")
                st.metric("Total Reports", ab.get('totalReports'))
            else: st.info("רלוונטי ל-IP בלבד.")

with tab_map:
    components.iframe("https://threatmap.checkpoint.com/", height=700)

st.markdown("""<div class="footer">SYSTEM ARCHITECT: <b>LIDOR AVRAHAMY</b></div>""", unsafe_allow_html=True)

