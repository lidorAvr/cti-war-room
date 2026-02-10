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
    return cnt
