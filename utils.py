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
# --- FIX: Updated Import for Stability ---
from duckduckgo_search import DDGS
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
    now = datetime.datetime.now(IL_TZ)
    try:
        if isinstance(date_obj, time.struct_time):
            dt = datetime.datetime(*date_obj[:6], tzinfo=pytz.utc)
            return dt.astimezone(IL_TZ).isoformat()
        if isinstance(date_obj, str):
            dt = date_parser.parse(date_obj)
            if dt.tzinfo is None: dt = pytz.utc.localize(dt)
            return dt.astimezone(IL_TZ).isoformat()
        if isinstance(date_obj, datetime.datetime):
            if date_obj.tzinfo is None: date_obj = pytz.utc.localize(date_obj)
            return date_obj.astimezone(IL_TZ).isoformat()
    except: pass
    return now.isoformat()

# --- IOC VALIDATION ---
def identify_ioc_type(ioc):
    ioc = ioc.strip()
    if re.match(r'^https?://', ioc) or re.match(r'^www\.', ioc): return "url"
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError: pass
    if re.match(r'^[a-fA-F0-9]{32}$', ioc) or re.match(r'^[a-fA-F0-9]{40}$', ioc) or re.match(r'^[a-fA-F0-9]{64}$', ioc): return "hash"
    if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', ioc): return "domain"
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
    c.execute("CREATE INDEX IF NOT EXISTS idx_title ON intel_reports(title)")
    limit_regular = (datetime.datetime.now(IL_TZ) - datetime.timedelta(days=7)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE source NOT IN ('INCD', 'DeepWeb') AND published_at < ?", (limit_regular,))
    conn.commit()
    conn.close()

def get_existing_data():
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT url, title FROM intel_reports")
        rows = c.fetchall()
        conn.close()
        return {row[0] for row in rows}, {row[1] for row in rows}
    except: return set(), set()

# --- DEEP WEB SCANNER ---
class DeepWebScanner:
    def scan_actor(self, actor_name, limit=3):
        results = []
        try:
            query = f'"{actor_name}" cyber threat intelligence malware analysis report'
            with DDGS() as ddgs:
                ddg_results = list(ddgs.text(query, max_results=limit))
                existing_urls, _ = get_existing_data()
                for res in ddg_results:
                    url = res.get('href')
                    if url in existing_urls: continue
                    results.append({
                        "title": res.get('title'),
                        "url": url,
                        "date": datetime.datetime.now(IL_TZ).isoformat(),
                        "source": "DeepWeb",
                        "summary": res.get('body', 'No summary available.'),
                        "actor_tag": actor_name
                    })
        except Exception as e: print(f"Deep Scan Error: {e}")
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

def polish_with_gemini(text_content):
    try:
        gemini_key = st.secrets.get("gemini_key")
        if not gemini_key: return text_content
        genai.configure(api_key=gemini_key)
        model = genai.GenerativeModel('gemini-pro')
        
        prompt = f"""
        Act as a Senior Cyber Intelligence Officer (Unit 8200).
        Task: Rewrite the following intelligence report for a CISO.
        
         Directives:
        1. **Language**: High-level Operational Hebrew ONLY.
        2. **Terminology**:
           - "Breach" -> "אירוע דליפת מידע" / "חדירה לרשת".
           - "Attack" -> "מתקפה" / "קמפיין זדוני".
           - "Malware" -> "נוזקה".
           - "Vulnerability" -> "חולשה" / "פגיעות".
        3. **Style**: Factual, Concise, No "Machine Translation" feel.
        4. **Structure**: Ensure flow between points.
        
        Text:
        {text_content}
        """
        response = model.generate_content(prompt)
        return response.text
    except: return text_content

class AIBatchProcessor:
    def __init__(self, key):
        self.key = key
    
    def _determine_tag_severity(self, text, source):
        text = text.lower()
        sev, tag = "Medium", "כללי"
        if any(x in text for x in ['exploited', 'zero-day', 'ransomware', 'critical', 'cve-202', 'apt', 'state-sponsored']): sev = "High"
        if source == "INCD" or "israel" in text or "iran" in text: tag = "ישראל"
        elif "cve-" in text or "patch" in text or "vulnerability" in text: tag = "פגיעויות"
        elif "phishing" in text or "credential" in text: tag = "פיישינג"
        elif "malware" in text or "trojan" in text or "backdoor" in text: tag = "נוזקה"
        elif "research" in text or "analysis" in text: tag = "מחקר"
        return tag, sev

    async def analyze_batch(self, items):
        if not items: return []
        existing_urls, existing_titles = get_existing_data()
        
        items_to_process = [i for i in items if i['url'] not in existing_urls]
        if not items_to_process: return []

        chunk_size = 10
        results = []
        
        system_instruction = """
        You are a Senior Cyber Intelligence Analyst.
        
        **MISSION:**
        1. **CLUSTER & DEDUPLICATE**: Group news items that talk about the SAME event.
        2. **SYNTHESIZE**: For each unique event, write ONE comprehensive report.
        3. **LANGUAGE**: Hebrew ONLY.
        
        **REPORT STRUCTURE:**
        - **Title**: Operational Hebrew Title.
        - **Summary**:
            • **תמונת מצב**: What happened? (Fact based).
            • **ממצאים טכניים**: CVEs, Malware names, TTPs.
            • **משמעויות**: Impact and Mitigation.

        **Output JSON:**
        {"items": [
            {
                "source_url": "URL of the BEST/NEWEST source for this event",
                "title": "Hebrew Title",
                "summary": "The structured 3-part summary in Hebrew"
            }
        ]}
        """
        
        for i in range(0, len(items_to_process), chunk_size):
            chunk = items_to_process[i:i+chunk_size]
            
            batch_text = ""
            for idx, x in enumerate(chunk):
                batch_text += f"ITEM {idx} | URL: {x['url']} | Title: {x['title']} | Content Snippet: {x['summary'][:1000]}\n\n"
            
            prompt = f"{system_instruction}\n\nRAW INTELLIGENCE:\n{batch_text}"
            
            res = await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=True)
            
            if res:
                try:
                    data = json.loads(res)
                    processed_items = data.get("items", [])
                    
                    for p_item in processed_items:
                        original = next((x for x in chunk if x['url'] == p_item.get('source_url')), None)
                        if not original: original = chunk[0]

                        if any(p_item.get('title') in t for t in existing_titles): continue

                        final_title = polish_with_gemini(p_item.get('title'))
                        final_summary = polish_with_gemini(p_item.get('summary'))
                        
                        tag_text = final_title + final_summary
                        final_tag, final_sev = self._determine_tag_severity(tag_text, original['source'])

                        results.append({
                            "category": "News", 
                            "severity": final_sev, 
                            "title": final_title, 
                            "summary": final_summary,
                            "published_at": original['date'],
                            "source": original['source'], 
                            "url": original['url'],       
                            "actor_tag": original.get('actor_tag', None),
                            "tags": final_tag
                        })
                        existing_titles.add(final_title)
                except: pass
                    
        return results

    async def analyze_single_ioc(self, ioc, ioc_type, data):
        lean_data = self._extract_key_intel(data)
        prompt = f"Act as Senior SOC Analyst. Target: {ioc} ({ioc_type}). Data: {json.dumps(lean_data)}. Output Hebrew Markdown analysis."
        res = await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)
        return res if res else "שגיאה בניתוח."

    def _extract_key_intel(self, raw_data):
        summary = {}
        if 'virustotal' in raw_data and raw_data['virustotal']:
            vt = raw_data['virustotal']
            summary['virustotal'] = {'malicious_votes': vt.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0), 'tags': vt.get('attributes', {}).get('tags', [])}
        return summary

class ThreatLookup:
    def __init__(self, vt_key=None, urlscan_key=None, abuse_key=None):
        self.vt_key, self.urlscan_key, self.abuse_key = vt_key, urlscan_key, abuse_key
    def query_virustotal(self, ioc, ioc_type):
        if not self.vt_key: return None
        try:
            endpoint = f"urls/{base64.urlsafe_b64encode(ioc.encode()).decode().strip('=')}" if ioc_type == "url" else f"{'ip_addresses' if ioc_type == 'ip' else 'domains' if ioc_type == 'domain' else 'files'}/{ioc}"
            res = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}", headers={"x-apikey": self.vt_key}, timeout=10)
            return res.json().get('data', {}) if res.status_code == 200 else None
        except: return None
    def query_urlscan(self, ioc):
        if not self.urlscan_key: return None
        try:
            res = requests.get(f"https://urlscan.io/api/v1/search/?q=\"{ioc}\"", headers={"API-Key": self.urlscan_key}, timeout=10)
            data = res.json()
            if data.get('results'):
                return requests.get(f"https://urlscan.io/api/v1/result/{data['results'][0]['_id']}/", headers={"API-Key": self.urlscan_key}, timeout=10).json()
            return None
        except: return None
    def query_abuseipdb(self, ip):
        if not self.abuse_key: return None
        try:
            return requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': self.abuse_key}, params={'ipAddress': ip}, timeout=10).json().get('data', {})
        except: return None

class AnalystToolkit:
    @staticmethod
    def get_tools():
        return {
            "Analysis": [{"name": "CyberChef", "url": "https://gchq.github.io/CyberChef/", "desc": "פענוח", "icon": "🔪"},{"name": "Any.Run", "url": "https://app.any.run/", "desc": "Sandbox", "icon": "📦"},{"name": "UnpacMe", "url": "https://www.unpac.me/", "desc": "Unpacking", "icon": "🔓"}],
            "Lookup": [{"name": "VirusTotal", "url": "https://www.virustotal.com/", "desc": "Scanner", "icon": "🦠"},{"name": "AbuseIPDB", "url": "https://www.abuseipdb.com/", "desc": "Reputation", "icon": "🚫"},{"name": "Talos", "url": "https://talosintelligence.com/", "desc": "Intel", "icon": "🛡️"}],
            "Tools": [{"name": "MxToolbox", "url": "https://mxtoolbox.com/", "desc": "Network", "icon": "🔧"},{"name": "URLScan", "url": "https://urlscan.io/", "desc": "Web Scan", "icon": "📷"},{"name": "OTX", "url": "https://otx.alienvault.com/", "desc": "Open Intel", "icon": "👽"}]
        }

class APTSheetCollector:
    def fetch_threats(self): 
        return [
            {"name": "MuddyWater", "origin": "Iran (MOIS)", "target": "Israel", "type": "Espionage", "tools": "PowerShell, Ligolo", "desc": "מזוהה עם משרד המודיעין האיראני."},
            {"name": "OilRig (APT34)", "origin": "Iran (IRGC)", "target": "Israel", "type": "Espionage", "tools": "DNSpionage", "desc": "מתמקדת בתשתיות קריטיות."},
            {"name": "Agonizing Serpens", "origin": "Iran", "target": "Israel", "type": "Wiper", "tools": "BiBiWiper", "desc": "מטרתה השמדת מידע."}
        ]

class CTICollector:
    SOURCES = [
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "TheHackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        {"name": "INCD", "url": "https://www.gov.il/he/rss/news_list?officeId=4bcc13f5-fed6-4b8c-b8ee-7bf4a6bc81c8", "type": "rss"},
        {"name": "INCD", "url": "https://t.me/s/Israel_Cyber", "type": "telegram"},
        {"name": "Malwarebytes", "url": "https://www.malwarebytes.com/blog/feed/", "type": "rss"}
    ]

    async def fetch_item(self, session, source):
        items = []
        try:
            async with session.get(source['url'], headers=HEADERS, timeout=25) as resp:
                if resp.status != 200: return []
                content = await resp.text()
                if source['type'] == 'rss':
                    feed = feedparser.parse(content)
                    for entry in feed.entries[:30]:
                        date_raw = getattr(entry, 'published_parsed', None) or getattr(entry, 'updated_parsed', None)
                        items.append({"title": entry.title, "url": entry.link, "date": parse_flexible_date(date_raw), "source": source['name'], "summary": BeautifulSoup(entry.summary, "html.parser").get_text()[:2500]})
                elif source['type'] == 'json':
                     data = json.loads(content)
                     for v in data.get('vulnerabilities', [])[:20]:
                         items.append({"title": f"KEV: {v['cveID']}", "url": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}", "date": parse_flexible_date(v.get('dateAdded')), "source": "CISA", "summary": v.get('shortDescription')})
                elif source['type'] == 'telegram':
                    soup = BeautifulSoup(content, 'html.parser')
                    for msg in soup.find_all('div', class_='tgme_widget_message_wrap')[-20:]:
                        try:
                            text = msg.find('div', class_='tgme_widget_message_text').get_text(separator=' ')
                            items.append({"title": "התרעת מערך הסייבר", "url": msg.find('a', class_='tgme_widget_message_date')['href'], "date": parse_flexible_date(msg.find('time')['datetime']), "source": "INCD", "summary": text})
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
    for item in analyzed:
        try:
            c.execute("INSERT OR IGNORE INTO intel_reports (timestamp,published_at,source,url,title,category,severity,summary,actor_tag,tags) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (datetime.datetime.now(IL_TZ).isoformat(), item['published_at'], item['source'], item['url'], item['title'], item['category'], item['severity'], item['summary'], item.get('actor_tag'), item.get('tags')))
            if c.rowcount > 0: cnt += 1
        except: pass
    conn.commit()
    conn.close()
    return cnt
