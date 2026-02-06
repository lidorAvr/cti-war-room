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
from ddgs import DDGS
import streamlit as st

DB_NAME = "cti_dashboard.db"
IL_TZ = pytz.timezone('Asia/Jerusalem')

# --- HTTP HEADERS (Improved to avoid blocks) ---
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'he-IL,he;q=0.9,en-US;q=0.8,en;q=0.7',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache'
}

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
    
    # Retention Policy
    limit_regular = (datetime.datetime.now(IL_TZ) - datetime.timedelta(hours=48)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE source NOT IN ('INCD', 'DeepWeb') AND published_at < ?", (limit_regular,))
    
    # Migrations
    try: c.execute("ALTER TABLE intel_reports ADD COLUMN tags TEXT")
    except: pass
    try: c.execute("ALTER TABLE intel_reports ADD COLUMN actor_tag TEXT")
    except: pass

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
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
    if json_mode: payload["response_format"] = {"type": "json_object"}
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, json=payload, headers=headers, timeout=50) as resp:
                data = await resp.json()
                if resp.status == 200: return data['choices'][0]['message']['content']
                return f"Error {resp.status}"
        except Exception as e: return f"Connection Error: {e}"

class AIBatchProcessor:
    def __init__(self, key):
        self.key = key
    
    def _force_tags_and_severity(self, title, summary, current_tag, current_sev):
        """
        Double-Check Mechanism: Forces tags based on keywords to avoid 'General'
        """
        txt = (title + " " + summary).lower()
        
        # 1. Force Severity
        if any(x in txt for x in ['exploited', 'zero-day', 'ransomware', 'critical', 'cve-2025', 'cve-2024']):
            if current_sev in ['Medium', 'Low']:
                current_sev = 'High'
        
        # 2. Force Tags
        new_tag = current_tag
        if 'cve-' in txt or 'vulnerability' in txt or 'patch' in txt or 'flaw' in txt or 'exploit' in txt:
            new_tag = 'פגיעויות'
        elif 'ransomware' in txt or 'malware' in txt or 'backdoor' in txt or 'trojan' in txt or 'spyware' in txt:
            new_tag = 'נוזקה'
        elif 'phishing' in txt or 'social engineering' in txt or 'credential' in txt:
            new_tag = 'פיישינג'
        elif 'israel' in txt or 'iran' in txt or 'gaza' in txt or 'incd' in txt:
            new_tag = 'ישראל'
            
        return new_tag, current_sev

    async def analyze_batch(self, items):
        if not items: return []
        chunk_size = 5 
        results = []
        
        # --- PROMPT: DIRECT HEBREW TRANSLATION ---
        system_instruction = """
        You are an expert Cyber Intelligence Analyst for the Israeli National Cyber Directorate.
        
        TASK: Analyze the provided cyber security news items.
        
        OUTPUT FORMAT (JSON ONLY):
        {
            "items": [
                {
                    "id": 0,
                    "title": "WRITE HERE THE TITLE IN HEBREW (Formal)",
                    "summary": "WRITE HERE A TECHNICAL SUMMARY IN HEBREW (3 sentences). Keep technical terms (CVE, Malware Names, Ransomware) in ENGLISH.",
                    "severity": "Critical/High/Medium/Low",
                    "tag": "Phishing/Malware/Vulnerabilities/Israel/Research/General",
                    "published_at": "ISO8601 Date"
                }
            ]
        }
        
        RULES:
        1. **Language**: Title and Summary MUST be in Hebrew (עברית).
        2. **Severity**: Ransomware/Active Exploit = High/Critical.
        3. **Date**: Extract the real publication date from text/context.
        """
        
        for i in range(0, len(items), chunk_size):
            chunk = items[i:i+chunk_size]
            batch_lines = [f"ID:{idx} | RawDate:{x['date']} | Source:{x['source']} | Content:{x['title']} - {x['summary'][:2000]}" for idx, x in enumerate(chunk)]
            batch_text = "\n".join(batch_lines)
            prompt = f"{system_instruction}\nRaw Data:\n{batch_text}"
            
            # Use Groq to do everything: Analysis + Translation + JSON
            res = await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=True)
            
            chunk_map = {}
            try:
                data = json.loads(res)
                for item in data.get("items", []): chunk_map[item.get('id')] = item
            except: pass
            
            for j in range(len(chunk)):
                ai = chunk_map.get(j, {})
                
                # Tag Mapping (Hebrew to Hebrew safety net)
                eng_tag_map = {
                    'Phishing': 'פיישינג', 'Malware': 'נוזקה', 'Vulnerabilities': 'פגיעויות',
                    'Israel': 'ישראל', 'Research': 'מחקר', 'General': 'כללי'
                }
                raw_tag = ai.get('tag', 'General')
                mapped_tag = eng_tag_map.get(raw_tag, raw_tag) # Handle if AI returns English
                
                # INCD Overrides
                if chunk[j]['source'] == 'INCD':
                    mapped_tag = 'ישראל'
                
                # Double Check Logic
                final_tag, final_sev = self._force_tags_and_severity(
                    ai.get('title', ''), 
                    ai.get('summary', ''), 
                    mapped_tag, 
                    ai.get('severity', 'Medium')
                )

                results.append({
                    "category": "News", 
                    "severity": final_sev, 
                    "title": ai.get('title', chunk[j]['title']), # Should be Hebrew from Prompt
                    "summary": ai.get('summary', chunk[j]['summary']), # Should be Hebrew from Prompt
                    "published_at": ai.get('published_at', chunk[j]['date']),
                    "actor_tag": chunk[j].get('actor_tag', None),
                    "tags": final_tag
                })
        return results

    async def analyze_single_ioc(self, ioc, ioc_type, data):
        lean_data = self._extract_key_intel(data)
        # --- PROMPT: HEBREW OUTPUT FOR IOC ---
        prompt = f"""
        Act as a Senior SOC Analyst in Israel.
        Target IOC: {ioc} ({ioc_type})
        Data: {json.dumps(lean_data)}
        
        Output Markdown (IN HEBREW):
        ### 🛡️ ניתוח מבצעי (Operational Verdict)
        * **פסק דין**: [זדוני / חשוד / נקי]
        * **רמת ביטחון**: [גבוהה / בינונית / נמוכה]
        * **הסבר**: Explain the reasoning in Hebrew.
        
        ### 🏢 המלצות הגנה (Defense Playbook)
        * **פעולות מומלצות**: List specific firewall/EDR actions in Hebrew.
        """
        return await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)

    def _extract_key_intel(self, raw_data):
        summary = {}
        if 'virustotal' in raw_data and raw_data['virustotal']:
            vt = raw_data['virustotal']
            summary['virustotal'] = {
                'stats': vt.get('attributes', {}).get('last_analysis_stats'),
                'reputation': vt.get('attributes', {}).get('reputation')
            }
        return summary

    async def generate_hunting_queries(self, actor):
        prompt = f"Generate Hunting Queries (XQL, YARA) for Actor: {actor['name']}. Tools: {actor.get('tools')}."
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
            
            res = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}", headers={"x-apikey": self.vt_key}, timeout=15)
            return res.json().get('data', {}) if res.status_code == 200 else None
        except: return None

    def query_urlscan(self, ioc):
        if not self.urlscan_key: return None
        try:
            # Step 1: Search
            res = requests.get(f"https://urlscan.io/api/v1/search/?q={ioc}", headers={"API-Key": self.urlscan_key}, timeout=15)
            data = res.json()
            if data.get('results'):
                # Step 2: Get Result
                scan_id = data['results'][0]['_id']
                return requests.get(f"https://urlscan.io/api/v1/result/{scan_id}/", headers={"API-Key": self.urlscan_key}).json()
            return None
        except: return None

    def query_abuseipdb(self, ip):
        if not self.abuse_key: return None
        try:
            res = requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': self.abuse_key, 'Accept': 'application/json'}, params={'ipAddress': ip}, timeout=10)
            return res.json().get('data', {})
        except: return None

class AnalystToolkit:
    @staticmethod
    def get_tools():
        # Enhanced Metadata for UI
        return {
            "Analysis": [
                {"name": "CyberChef", "url": "https://gchq.github.io/CyberChef/", "desc": "פענוח והמרה", "icon": "🔪"},
                {"name": "Any.Run", "url": "https://app.any.run/", "desc": "ארגז חול אינטראקטיבי", "icon": "📦"},
                {"name": "UnpacMe", "url": "https://www.unpac.me/", "desc": "פתיחת נוזקות", "icon": "🔓"}
            ],
            "Lookup": [
                {"name": "VirusTotal", "url": "https://www.virustotal.com/", "desc": "סריקת קבצים וכתובות", "icon": "🦠"},
                {"name": "AbuseIPDB", "url": "https://www.abuseipdb.com/", "desc": "מוניטין כתובות IP", "icon": "🚫"},
                {"name": "Talos", "url": "https://talosintelligence.com/", "desc": "מודיעין סיסקו", "icon": "🛡️"}
            ],
            "Tools": [
                {"name": "MxToolbox", "url": "https://mxtoolbox.com/", "desc": "כלי רשת ומייל", "icon": "🔧"},
                {"name": "URLScan", "url": "https://urlscan.io/", "desc": "סריקת אתרים", "icon": "📷"},
                {"name": "OTX", "url": "https://otx.alienvault.com/", "desc": "מודיעין פתוח", "icon": "👽"}
            ]
        }

class APTSheetCollector:
    def fetch_threats(self): 
        return [
            {"name": "MuddyWater", "origin": "Iran", "target": "Israel", "type": "Espionage", "tools": "PowerShell, Ligolo", "keywords": ["muddywater", "static_kitten"], "desc": "MOIS-affiliated group targeting Israeli Gov.", "mitre": "T1059, T1105"},
            {"name": "OilRig (APT34)", "origin": "Iran", "target": "Israel", "type": "Espionage", "tools": "Karkoff, SideTwist", "keywords": ["oilrig", "apt34"], "desc": "Targeting critical infrastructure.", "mitre": "T1071, T1048"},
            {"name": "Agonizing Serpens", "origin": "Iran", "target": "Israel", "type": "Destructive", "tools": "BiBiWiper", "keywords": ["agonizing serpens", "bibiwiper"], "desc": "Destructive attacks disguised as ransomware.", "mitre": "T1485, T1486"}
        ]

class CTICollector:
    SOURCES = [
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "TheHackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        {"name": "INCD", "url": "https://www.gov.il/he/rss/news_list?officeId=4bcc13f5-fed6-4b8c-b8ee-7bf4a6bc81c8", "type": "rss"},
        {"name": "INCD", "url": "https://t.me/s/Israel_Cyber", "type": "telegram"} 
    ]

    async def fetch_item(self, session, source):
        items = []
        try:
            async with session.get(source['url'], headers=HEADERS, timeout=25) as resp:
                if resp.status != 200: return []
                content = await resp.text()
                now = datetime.datetime.now(IL_TZ)
                
                # --- RSS PARSER ---
                if source['type'] == 'rss':
                    feed = feedparser.parse(content)
                    
                    # Logic: If INCD, take top 4 NO MATTER WHAT. Else take top 5.
                    if source['name'] == 'INCD':
                        entries_to_check = feed.entries[:4] # Force top 4
                    else:
                        entries_to_check = feed.entries[:5]

                    for entry in entries_to_check:
                        pub_date = now
                        try:
                            if hasattr(entry, 'published_parsed'): 
                                pub_date = datetime.datetime(*entry.published_parsed[:6]).replace(tzinfo=pytz.utc).astimezone(IL_TZ)
                        except: pass
                        
                        # Filter out old news ONLY if NOT INCD
                        if source['name'] != 'INCD' and (now - pub_date).total_seconds() > 172800: continue
                        if _is_url_processed(entry.link): continue
                        
                        items.append({"title": entry.title, "url": entry.link, "date": pub_date.isoformat(), "source": source['name'], "summary": BeautifulSoup(entry.summary, "html.parser").get_text()[:600]})

                # --- JSON PARSER ---
                elif source['type'] == 'json':
                     data = json.loads(content)
                     for v in data.get('vulnerabilities', [])[:5]:
                         url = f"https://nvd.nist.gov/vuln/detail/{v['cveID']}" # Fixed Link
                         if _is_url_processed(url): continue
                         items.append({"title": f"KEV: {v['cveID']}", "url": url, "date": now.isoformat(), "source": "CISA", "summary": v.get('shortDescription')})
                
                # --- TELEGRAM PARSER ---
                elif source['type'] == 'telegram':
                    soup = BeautifulSoup(content, 'html.parser')
                    msgs = soup.find_all('div', class_='tgme_widget_message_wrap')
                    # Force 4 last messages for INCD Telegram
                    for msg in msgs[-4:]:
                        try:
                            text_div = msg.find('div', class_='tgme_widget_message_text')
                            if not text_div: continue
                            text = text_div.get_text(separator=' ')
                            
                            pub_date = now
                            # Try extract date
                            time_tag = msg.find('time')
                            if time_tag and 'datetime' in time_tag.attrs:
                                try: pub_date = date_parser.parse(time_tag['datetime']).astimezone(IL_TZ)
                                except: pass
                                
                            link_tag = msg.find('a', class_='tgme_widget_message_date')
                            post_link = link_tag['href'] if link_tag else source['url']
                            
                            if _is_url_processed(post_link): continue
                            
                            items.append({"title": "התרעת מערך הסייבר (טלגרם)", "url": post_link, "date": pub_date.isoformat(), "source": "INCD", "summary": text[:800]})
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
    for i, item in enumerate(raw):
        if i < len(analyzed):
            a = analyzed[i]
            final_date = a.get('published_at', item['date'])
            try:
                c.execute("INSERT OR IGNORE INTO intel_reports (timestamp,published_at,source,url,title,category,severity,summary,actor_tag,tags) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (datetime.datetime.now(IL_TZ).isoformat(), final_date, item['source'], item['url'], a['title'], a['category'], a['severity'], a['summary'], a.get('actor_tag'), a.get('tags')))
                if c.rowcount > 0: cnt += 1
            except: pass
    conn.commit()
    conn.close()
    return cnt
