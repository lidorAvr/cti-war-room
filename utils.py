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
import google.generativeai as genai
import streamlit as st

DB_NAME = "cti_dashboard.db"
IL_TZ = pytz.timezone('Asia/Jerusalem')

# --- HTTP HEADERS ---
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9,he;q=0.8',
    'Referer': 'https://www.google.com/'
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
    # Added 'tags' column
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
    
    # Clean old data but keep INCD and DeepWeb scans longer
    limit_regular = (datetime.datetime.now(IL_TZ) - datetime.timedelta(hours=48)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE source NOT IN ('INCD', 'DeepWeb') AND published_at < ?", (limit_regular,))
    
    # Migrations
    try: c.execute("ALTER TABLE intel_reports ADD COLUMN actor_tag TEXT")
    except: pass
    try: c.execute("ALTER TABLE intel_reports ADD COLUMN tags TEXT")
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

async def query_groq_api(api_key, prompt, model="llama-3.1-8b-instant", json_mode=True):
    if not api_key: return "Error: Missing API Key"
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
    if json_mode: payload["response_format"] = {"type": "json_object"}
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, json=payload, headers=headers, timeout=40) as resp:
                data = await resp.json()
                if resp.status == 200: return data['choices'][0]['message']['content']
                return f"Error {resp.status}: {data.get('error', {}).get('message', 'Unknown error')}"
        except Exception as e: return f"Connection Error: {e}"

def translate_with_gemini_hebrew(text_content):
    """
    Translates to Hebrew using Gemini. Fallback to input if key missing.
    """
    try:
        # Check for 'gemini_key' specifically
        gemini_key = st.secrets.get("gemini_key")
        if not gemini_key:
            return text_content + " (Gemini Key Missing)"
        
        genai.configure(api_key=gemini_key)
        model = genai.GenerativeModel('gemini-pro')
        
        prompt = f"""
        Translate the following Cyber Security text to Hebrew.
        Target Audience: Israeli SOC Analysts.
        Rules:
        1. Keep technical terms in English (e.g. Ransomware, C2, Phishing, CVE).
        2. Tone: Professional, informative.
        3. Output ONLY the translation.
        
        Text:
        {text_content}
        """
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return text_content

class AIBatchProcessor:
    def __init__(self, key):
        self.key = key
        
    async def analyze_batch(self, items):
        if not items: return []
        chunk_size = 5 
        results = []
        
        # PROMPT: Extract Tags, Severity, Date
        system_instruction = """
        You are a CTI Analyst. Analyze these news items.
        
        OUTPUT JSON format:
        {
            "items": [
                {
                    "id": 0,
                    "title": "Concise Title",
                    "summary": "Technical summary (3 sentences). Mention Actor/Malware.",
                    "severity": "Critical/High/Medium/Low",
                    "tag": "Select ONE: Phishing, Malware, Vulnerabilities, Israel, Research, General",
                    "published_at": "ISO8601 Date (Extract from text context or use raw date)"
                }
            ]
        }
        
        RULES:
        1. **Severity**: If Ransomware / Active Exploitation / APT -> High/Critical.
        2. **Tags**:
           - 'Israel': If mentions Israel, INCD, or Israeli targets.
           - 'Vulnerabilities': If mentions CVE, Patch, Exploit.
           - 'Phishing': If mentions Social Engineering, Credentials.
           - 'Malware': If mentions Trojans, Backdoors, Rats.
        """
        
        for i in range(0, len(items), chunk_size):
            chunk = items[i:i+chunk_size]
            batch_lines = [f"ID:{idx} | RawDate:{x['date']} | Content:{x['title']} - {x['summary'][:2000]}" for idx, x in enumerate(chunk)]
            batch_text = "\n".join(batch_lines)
            prompt = f"{system_instruction}\nRaw Data:\n{batch_text}"
            
            res = await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=True)
            
            chunk_map = {}
            try:
                data = json.loads(res)
                for item in data.get("items", []): chunk_map[item.get('id')] = item
            except: pass
            
            for j in range(len(chunk)):
                ai = chunk_map.get(j, {})
                
                # Severity Boost Logic
                sev = ai.get('severity', 'Medium')
                raw_txt = (chunk[j]['title'] + chunk[j]['summary']).lower()
                if 'ransomware' in raw_txt or 'exploited' in raw_txt or 'zero-day' in raw_txt:
                    if sev in ['Medium', 'Low']: sev = 'High'
                
                # Tag Translation Mapping
                eng_tag = ai.get('tag', 'General')
                tag_map = {
                    'Phishing': 'פיישינג',
                    'Malware': 'נוזקה',
                    'Vulnerabilities': 'פגיעויות',
                    'Israel': 'ישראל',
                    'Research': 'מחקר',
                    'General': 'כללי'
                }
                final_tag = tag_map.get(eng_tag, 'כללי')
                if chunk[j]['source'] == 'INCD': final_tag = 'ישראל'

                # Translation
                eng_title = ai.get('title', chunk[j]['title'])
                eng_sum = ai.get('summary', chunk[j]['summary'][:400])
                
                heb_title = translate_with_gemini_hebrew(eng_title)
                heb_sum = translate_with_gemini_hebrew(eng_sum)

                results.append({
                    "category": "News", 
                    "severity": sev, 
                    "title": heb_title,
                    "summary": heb_sum,
                    "published_at": ai.get('published_at', chunk[j]['date']),
                    "actor_tag": chunk[j].get('actor_tag', None),
                    "tags": final_tag
                })
        return results

    async def analyze_single_ioc(self, ioc, ioc_type, data):
        lean_data = self._extract_key_intel(data)
        prompt = f"""
        Act as Senior SOC Analyst. Target IOC: {ioc} ({ioc_type}).
        Data: {json.dumps(lean_data)}
        Output Markdown (English):
        ### 🛡️ Operational Verdict
        * **Verdict**: [Malicious/Suspicious/Clean]
        * **Confidence**: [High/Medium/Low]
        * **Reasoning**: Why?
        ### 🏢 Defense Playbook
        * **Action**: Firewall/EDR rules.
        """
        return await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)

    def _extract_key_intel(self, raw_data):
        summary = {}
        if 'virustotal' in raw_data:
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
            res = requests.get(f"https://urlscan.io/api/v1/search/?q={ioc}", headers={"API-Key": self.urlscan_key}, timeout=15)
            data = res.json()
            if data.get('results'):
                return requests.get(f"https://urlscan.io/api/v1/result/{data['results'][0]['_id']}/", headers={"API-Key": self.urlscan_key}).json()
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
        return {
            "Analysis": [
                {"name": "CyberChef", "url": "https://gchq.github.io/CyberChef/", "desc": "Decoding"},
                {"name": "Any.Run", "url": "https://app.any.run/", "desc": "Sandbox"}
            ],
            "Lookup": [
                {"name": "VirusTotal", "url": "https://www.virustotal.com/", "desc": "IOC Scanner"},
                {"name": "AbuseIPDB", "url": "https://www.abuseipdb.com/", "desc": "IP Reputation"},
                {"name": "Talos", "url": "https://talosintelligence.com/", "desc": "Intel"}
            ],
            "Tools": [
                {"name": "MxToolbox", "url": "https://mxtoolbox.com/", "desc": "Network Tools"},
                {"name": "URLScan", "url": "https://urlscan.io/", "desc": "Web Scanner"}
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
        {"name": "INCD", "url": "https://www.gov.il/he/rss/news_list?officeId=4bcc13f5-fed6-4b8c-b8ee-7bf4a6bc81c8", "type": "rss"}
    ]

    async def fetch_item(self, session, source):
        items = []
        try:
            async with session.get(source['url'], headers=HEADERS, timeout=25) as resp:
                if resp.status != 200: return []
                content = await resp.text()
                now = datetime.datetime.now(IL_TZ)
                
                if source['type'] == 'rss':
                    feed = feedparser.parse(content)
                    # INCD: Take top 4 always. Others: Top 5
                    limit = 4 if source['name'] == 'INCD' else 5
                    
                    for entry in feed.entries[:limit]:
                        pub_date = now
                        try:
                            if hasattr(entry, 'published_parsed'): 
                                pub_date = datetime.datetime(*entry.published_parsed[:6]).replace(tzinfo=pytz.utc).astimezone(IL_TZ)
                        except: pass
                        
                        # Only apply 48h filter to NON-INCD sources
                        if source['name'] != 'INCD' and (now - pub_date).total_seconds() > 172800: continue
                        if _is_url_processed(entry.link): continue
                        
                        items.append({"title": entry.title, "url": entry.link, "date": pub_date.isoformat(), "source": source['name'], "summary": BeautifulSoup(entry.summary, "html.parser").get_text()[:600]})

                elif source['type'] == 'json':
                     data = json.loads(content)
                     for v in data.get('vulnerabilities', [])[:5]:
                         # FIX: Use NVD URL instead of CISA direct link to avoid Access Denied
                         url = f"https://nvd.nist.gov/vuln/detail/{v['cveID']}"
                         if _is_url_processed(url): continue
                         items.append({"title": f"KEV: {v['cveID']}", "url": url, "date": now.isoformat(), "source": "CISA", "summary": v.get('shortDescription')})
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
