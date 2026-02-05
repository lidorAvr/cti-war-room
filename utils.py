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
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from dateutil import parser as date_parser

DB_NAME = "cti_dashboard.db"
IL_TZ = pytz.timezone('Asia/Jerusalem')

# --- HTTP HEADERS (Anti-Bot & Localization) ---
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9,he;q=0.8',
    'Referer': 'https://www.google.com/'
}

# --- IOC VALIDATION (Existing) ---
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

# --- DATABASE MANAGEMENT (Existing) ---
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
        summary TEXT
    )''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_url ON intel_reports(url)")
    # Keep INCD data longer, flush generic news after 3 days
    limit_regular = (datetime.datetime.now(IL_TZ) - datetime.timedelta(days=3)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE source != 'INCD' AND published_at < ?", (limit_regular,))
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

# --- CONNECTION UTILS ---
class ConnectionManager:
    @staticmethod
    def check_groq(key):
        if not key: return False, "Missing Key"
        if key.startswith("gsk_"): return True, "Connected"
        return False, "Invalid Format"

async def query_groq_api(api_key, prompt, model="llama-3.1-8b-instant", json_mode=True):
    if not api_key: return "Error: Missing API Key"
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
    if json_mode: payload["response_format"] = {"type": "json_object"}
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, json=payload, headers=headers, timeout=60) as resp:
                data = await resp.json()
                if resp.status == 200: return data['choices'][0]['message']['content']
                return f"Error {resp.status}"
        except Exception as e: return f"Connection Error: {e}"

# --- THE BRAIN: AI PROCESSING & LOGIC ---
class AIBatchProcessor:
    def __init__(self, key):
        self.key = key

    # Advanced Severity Logic Matrix
    SEVERITY_KEYWORDS = {
        "Critical": ["active exploitation", "exploited in the wild", "cisa kev", "zero-day", "critical infrastructure", "nation-state", "hospital", "electric grid", "תשתיות קריטיות", "מתקפת סייבר רחבה", "cvss 9.8", "cvss 10"],
        "High": ["ransomware", "data leak", "data breach", "rce", "remote code execution", "poc available", "proof of concept", "cobalt strike", "כופרה", "דלף מידע", "cvss 8"],
        "Medium": ["xss", "dos", "defacement", "patch tuesday", "security update", "השחתת אתר"],
        "Low": ["statistics", "annual report", "conference", "minor bug", "סטטיסטיקה"]
    }

    def _calculate_deterministic_severity(self, item):
        """Overrides AI severity based on keyword matching + Israel Context."""
        txt = (item.get('title', '') + " " + item.get('raw_text', '')).lower()
        source = item.get('source', '')
        ai_severity = item.get('severity', 'Low')

        # 1. Absolute Rules
        if source == 'CISA KEV': return "Critical"
        if source == 'INCD' and ('התרעה' in txt or 'דחוף' in txt): return "Critical"

        # 2. Keyword Search (Priority Order)
        detected_level = None
        for level in ["Critical", "High", "Medium"]:
            for kw in self.SEVERITY_KEYWORDS[level]:
                if kw in txt: 
                    detected_level = level
                    break
            if detected_level: break
        
        # 3. Israel Context Boost
        if ("israel" in txt or "ישראל" in txt) and ("attack" in txt or "breach" in txt or "תקיפה" in txt or "נפרץ" in txt):
            if detected_level == "Medium" or not detected_level: detected_level = "High"
            elif detected_level == "High": detected_level = "Critical"

        # 4. Compare with AI result - take the stricter one
        sev_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}
        if sev_map.get(detected_level, 0) >= sev_map.get(ai_severity, 0):
            return detected_level if detected_level else ai_severity
        return ai_severity

    async def analyze_batch(self, items):
        if not items: return []
        chunk_size = 5 # Small chunks for enriched content
        results = []
        
        system_instruction = """
        You are a Senior CTI Analyst. Standardize intelligence.
        
        INPUT: Enriched raw content (ID, Source, Date, Text).
        
        OUTPUT RULES (JSON):
        1. **Title**: Professional CTI header (Max 8 words). IF INCD/Telegram -> HEBREW. ELSE -> ENGLISH.
        2. **Summary**: 3-4 bullet points. Focus on: **Target, Impact, IOCs**. IF INCD/Telegram -> HEBREW. ELSE -> ENGLISH.
        3. **Category**: "Phishing", "Malware", "Vulnerabilities", "Ransomware", "Data Leak", "Israel", "General".
        4. **Severity**: Critical (Active Exploit), High (Ransomware/Breach), Medium (Patches), Low (Info).
        5. **corrected_date**: 
           - Compare 'suspected_date' with the text.
           - IF the text explicitly says "Published: YYYY-MM-DD" or "Yesterday" and it differs, output the corrected ISO date.
           - OTHERWISE, omit this field.
        
        JSON Structure: {"items": [{"id": 0, "title": "...", "summary": "...", "category": "...", "severity": "...", "corrected_date": "OPTIONAL"}]}
        """
        
        for i in range(0, len(items), chunk_size):
            chunk = items[i:i+chunk_size]
            batch_text = ""
            for idx, x in enumerate(chunk):
                # Limit text to 1500 chars to save tokens but keep context
                clean_text = x['raw_text'][:1500].replace("\n", " ") 
                batch_text += f"\n[ID: {idx}] | Source: {x['source']} | Suspected Date: {x['date']} | Content: {clean_text}"
            
            prompt = f"{system_instruction}\n\nRAW DATA:{batch_text}"
            res = await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=True)
            
            chunk_map = {}
            try:
                data = json.loads(res)
                for item in data.get("items", []): chunk_map[item.get('id')] = item
            except: pass
            
            for j in range(len(chunk)):
                ai_res = chunk_map.get(j, {})
                
                # Logic Step 1: Date Correction
                final_date = ai_res.get('corrected_date') if ai_res.get('corrected_date') else chunk[j]['date']
                
                # Logic Step 2: Severity Calculation
                temp_item = {
                    "title": ai_res.get('title', chunk[j].get('title', '')),
                    "raw_text": chunk[j]['raw_text'],
                    "source": chunk[j]['source'],
                    "severity": ai_res.get('severity', 'Low')
                }
                final_severity = self._calculate_deterministic_severity(temp_item)
                
                results.append({
                    "title": temp_item['title'],
                    "summary": ai_res.get('summary', 'Analysis Failed'),
                    "category": ai_res.get('category', 'General'),
                    "severity": final_severity,
                    "url": chunk[j]['url'],
                    "source": chunk[j]['source'],
                    "date": final_date
                })
        return results

    # Keeps existing IOC analysis logic
    async def analyze_single_ioc(self, ioc, ioc_type, data):
        lean_data = self._extract_key_intel(data)
        prompt = f"Analyze IOC: {ioc} ({ioc_type}). Data: {json.dumps(lean_data)}. Output MarkDown."
        return await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)

    def _extract_key_intel(self, raw_data):
        summary = {}
        if 'virustotal' in raw_data and isinstance(raw_data['virustotal'], dict):
            vt = raw_data['virustotal']
            summary['virustotal'] = {
                'reputation': vt.get('attributes', {}).get('reputation'),
                'stats': vt.get('attributes', {}).get('last_analysis_stats')
            }
        return summary
    
    async def generate_hunting_queries(self, actor):
        prompt = f"Generate Hunting Queries (KQL/XQL) for actor: {actor['name']}. Tools: {actor.get('tools')}."
        return await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)


# --- THE EYES: COLLECTION & ENRICHMENT ---
class CTICollector:
    SOURCES = [
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss_tech"},
        {"name": "HackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss_tech"},
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss_tech"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json_cisa"},
        {"name": "INCD", "url": "https://www.gov.il/he/rss/news_list?officeId=4bcc13f5-fed6-4b8c-b8ee-7bf4a6bc81c8", "type": "rss_gov"},
        {"name": "INCD", "url": "https://t.me/s/Israel_Cyber", "type": "telegram"} 
    ]

    async def get_all_data(self):
        async with aiohttp.ClientSession() as session:
            tasks = []
            for s in self.SOURCES:
                if s['type'] == 'rss_tech': tasks.append(self._parse_rss_tech(session, s))
                elif s['type'] == 'rss_gov': tasks.append(self._parse_rss_gov(session, s))
                elif s['type'] == 'telegram': tasks.append(self._parse_telegram(session, s))
                elif s['type'] == 'json_cisa': tasks.append(self._parse_cisa(session, s))
            
            # Flatten results
            results = await asyncio.gather(*tasks)
            return [item for sublist in results for item in sublist]

    # --- ENRICHMENT CORE ---
    async def _enrich_url_content(self, session, url):
        """Scrapes the URL to find the full article body."""
        try:
            async with session.get(url, headers=HEADERS, timeout=10) as resp:
                if resp.status != 200: return None
                soup = BeautifulSoup(await resp.text(), "html.parser")
                
                # Cleanup
                for script in soup(["script", "style", "nav", "footer", "header", "aside", "iframe"]):
                    script.extract()
                
                # Extraction Heuristics
                content = ""
                if soup.find('article'):
                    content = soup.find('article').get_text(separator=' ')
                elif soup.find(class_=re.compile(r'post|article|content|story|body')):
                    content = soup.find(class_=re.compile(r'post|article|content|story|body')).get_text(separator=' ')
                else:
                    content = ' '.join([p.get_text() for p in soup.find_all('p')])
                
                clean = re.sub(r'\s+', ' ', content).strip()
                return clean if len(clean) > 100 else None
        except: return None

    # --- SPECIFIC PARSERS ---
    
    async def _parse_rss_tech(self, session, source):
        items = []
        try:
            async with session.get(source['url'], headers=HEADERS, timeout=20) as resp:
                if resp.status != 200: return []
                feed = feedparser.parse(await resp.text())
                
                # Only check top 4 to allow enrichment time
                for entry in feed.entries[:4]:
                    if _is_url_processed(entry.link): continue
                    
                    try: dt = datetime.datetime(*entry.published_parsed[:6]).replace(tzinfo=pytz.utc).astimezone(IL_TZ)
                    except: dt = datetime.datetime.now(IL_TZ)
                    
                    if (datetime.datetime.now(IL_TZ) - dt).days > 3: continue

                    # ENRICHMENT
                    enriched_text = await self._enrich_url_content(session, entry.link)
                    if not enriched_text:
                         # Fallback
                         raw_text = entry.title
                         if hasattr(entry, 'summary'): raw_text += "\n" + entry.summary
                         enriched_text = BeautifulSoup(raw_text, "html.parser").get_text(separator=' ')
                    
                    items.append({
                        "source": source['name'],
                        "url": entry.link,
                        "date": dt.isoformat(),
                        "raw_text": enriched_text,
                        "title": entry.title
                    })
        except: pass
        return items

    async def _parse_rss_gov(self, session, source):
        items = []
        try:
            async with session.get(source['url'], headers=HEADERS, timeout=20) as resp:
                feed = feedparser.parse(await resp.text())
                for entry in feed.entries[:5]:
                    if _is_url_processed(entry.link): continue
                    try: dt = datetime.datetime(*entry.published_parsed[:6]).replace(tzinfo=pytz.utc).astimezone(IL_TZ)
                    except: dt = datetime.datetime.now(IL_TZ)
                    
                    # INCD usually has good summaries, enrichment less critical here but possible
                    items.append({
                        "source": "INCD",
                        "url": entry.link,
                        "date": dt.isoformat(),
                        "raw_text": f"{entry.title}\n{entry.summary}",
                        "title": entry.title
                    })
        except: pass
        return items

    async def _parse_telegram(self, session, source):
        items = []
        try:
            async with session.get(source['url'], headers=HEADERS, timeout=20) as resp:
                soup = BeautifulSoup(await resp.text(), 'html.parser')
                msgs = soup.find_all('div', class_='tgme_widget_message_wrap')[-5:]
                
                for msg in msgs:
                    text_div = msg.find('div', class_='tgme_widget_message_text')
                    if not text_div: continue
                    raw_text = text_div.get_text(separator=' ')
                    
                    date_link = msg.find('a', class_='tgme_widget_message_date')
                    post_url = date_link['href'] if date_link else source['url']
                    
                    if _is_url_processed(post_url): continue
                    
                    # Specific Telegram Time Parsing
                    time_tag = msg.find('time')
                    if time_tag and 'datetime' in time_tag.attrs:
                        try: dt = date_parser.parse(time_tag['datetime']).astimezone(IL_TZ)
                        except: dt = datetime.datetime.now(IL_TZ)
                    else: dt = datetime.datetime.now(IL_TZ)

                    items.append({
                        "source": "INCD", 
                        "url": post_url,
                        "date": dt.isoformat(),
                        "raw_text": f"TELEGRAM ALERT: {raw_text}",
                        "title": "Telegram Alert"
                    })
        except: pass
        return items

    async def _parse_cisa(self, session, source):
        items = []
        try:
            async with session.get(source['url'], timeout=20) as resp:
                data = json.loads(await resp.text())
                for v in data.get('vulnerabilities', [])[:8]:
                    cve_url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?cve={v['cveID']}"
                    if _is_url_processed(cve_url): continue
                    
                    items.append({
                        "source": "CISA",
                        "url": cve_url,
                        "date": datetime.datetime.now(IL_TZ).isoformat(),
                        "raw_text": f"KEV Alert: {v['cveID']} - {v['vulnerabilityName']}. Description: {v['shortDescription']}",
                        "title": v['cveID']
                    })
        except: pass
        return items

# --- TOOLS & STATIC DATA (Existing) ---
class ThreatLookup:
    def __init__(self, vt_key=None, urlscan_key=None, abuse_key=None):
        self.vt_key, self.urlscan_key, self.abuse_key = vt_key, urlscan_key, abuse_key

    def query_virustotal(self, ioc, ioc_type):
        if not self.vt_key: return None
        try:
            endpoint = f"urls/{base64.urlsafe_b64encode(ioc.encode()).decode().strip('=')}" if ioc_type == "url" else \
                       f"ip_addresses/{ioc}" if ioc_type == "ip" else \
                       f"domains/{ioc}" if ioc_type == "domain" else f"files/{ioc}"
            
            res = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}", headers={"x-apikey": self.vt_key}, timeout=10)
            return res.json().get('data', {}) if res.status_code == 200 else None
        except: return None

    def query_urlscan(self, ioc):
        if not self.urlscan_key: return None
        try:
            res = requests.get(f"https://urlscan.io/api/v1/search/?q={ioc}", headers={"API-Key": self.urlscan_key}, timeout=10)
            if res.status_code == 200 and res.json().get('results'):
                uuid = res.json()['results'][0]['_id']
                return requests.get(f"https://urlscan.io/api/v1/result/{uuid}/", headers={"API-Key": self.urlscan_key}, timeout=10).json()
            return None
        except: return None

    def query_abuseipdb(self, ip):
        if not self.abuse_key: return None
        try:
            res = requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': self.abuse_key, 'Accept': 'application/json'}, params={'ipAddress': ip}, timeout=10)
            return res.json().get('data', {})
        except: return None

class APTSheetCollector:
    def fetch_threats(self): 
        return [
            {"name": "MuddyWater", "origin": "Iran", "type": "Espionage", "tools": "PowerShell, ScreenConnect", "desc": "Targeting Israeli Gov/Telecom.", "mitre": "T1059"},
            {"name": "OilRig (APT34)", "origin": "Iran", "type": "Espionage", "tools": "DNS Tunneling", "desc": "Sophisticated long-term access.", "mitre": "T1071"},
            {"name": "Handala Hack", "origin": "Pro-Palestinian", "type": "Hacktivism/Wiper", "tools": "Wipers, Phishing", "desc": "Targeting critical infrastructure.", "mitre": "T1485"}
        ]

def save_reports(raw, analyzed):
    conn = sqlite3.connect(DB_NAME)
    c, cnt = conn.cursor(), 0
    # analyzed matches raw 1:1 thanks to new logic, but safe loop just in case
    for item in analyzed:
        try:
            if _is_url_processed(item['url']): continue
            c.execute("INSERT OR IGNORE INTO intel_reports (timestamp,published_at,source,url,title,category,severity,summary) VALUES (?,?,?,?,?,?,?,?)",
                (datetime.datetime.now(IL_TZ).isoformat(), 
                 item['date'], # Using corrected date
                 item['source'], 
                 item['url'], 
                 item['title'], 
                 item['category'], 
                 item['severity'], 
                 item['summary']))
            if c.rowcount > 0: cnt += 1
        except Exception as e: pass
    conn.commit()
    conn.close()
    return cnt
