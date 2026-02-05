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

DB_NAME = "cti_dashboard.db"
IL_TZ = pytz.timezone('Asia/Jerusalem')

# --- HTTP HEADERS ---
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9,he;q=0.8',
    'Referer': 'https://www.google.com/'
}

# --- HELPER FUNCTIONS ---
def clean_html(raw_html):
    """Cleans HTML tags from text safely."""
    if not raw_html: return ""
    cleanr = re.compile('<.*?>')
    cleantext = re.sub(cleanr, '', str(raw_html))
    return cleantext.replace('"', '&quot;').strip()

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
        summary TEXT
    )''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_url ON intel_reports(url)")
    
    # Logic: Delete RSS older than 48h, but KEEP DeepWeb/INCD for history
    limit_regular = (datetime.datetime.now(IL_TZ) - datetime.timedelta(hours=48)).isoformat()
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

# --- DEEP WEB SCANNER (SMART & AUTOMATED) ---
class DeepWebScanner:
    def scan_actor(self, actor_name, limit=2):
        """Scans for Actor Activity - Runs Automatically via Collector"""
        results = []
        now = datetime.datetime.now(IL_TZ)
        
        try:
            query = f'"{actor_name}" cyber threat intelligence report'
            with DDGS() as ddgs:
                ddg_results = list(ddgs.text(query, max_results=limit))
                
                for res in ddg_results:
                    url = res.get('href')
                    if _is_url_processed(url): continue
                    
                    body = res.get('body', '')
                    title = res.get('title', '')
                    
                    # Try to extract REAL date from text
                    pub_date = now
                    try:
                        snippet_start = body[:150]
                        extracted_date = date_parser.parse(snippet_start, fuzzy=True)
                        if 2020 <= extracted_date.year <= now.year + 1:
                            pub_date = extracted_date.astimezone(IL_TZ)
                    except: pass
                    
                    results.append({
                        "title": title,
                        "url": url,
                        "date": pub_date.isoformat(),
                        "source": "DeepWeb",
                        "summary": body
                    })
        except Exception as e:
            print(f"Deep Scan Error: {e}")
        return results

    def scan_ioc(self, ioc, limit=4):
        """ACTIVE OSINT SCAN FOR IOC (Smart AI Feature)"""
        results = []
        try:
            query = f'"{ioc}" official site OR cyber security reputation OR malware analysis'
            with DDGS() as ddgs:
                ddg_results = list(ddgs.text(query, max_results=limit))
                for res in ddg_results:
                    results.append({
                        "title": res.get('title'),
                        "snippet": res.get('body'),
                        "source": "Web Search"
                    })
        except: pass
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
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.3}
    if json_mode: payload["response_format"] = {"type": "json_object"}
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, json=payload, headers=headers, timeout=30) as resp:
                data = await resp.json()
                if resp.status == 200: return data['choices'][0]['message']['content']
                return f"Error {resp.status}: {data.get('error', {}).get('message', 'Unknown error')}"
        except Exception as e: return f"Connection Error: {e}"

class AIBatchProcessor:
    def __init__(self, key):
        self.key = key
        
    def _prune_data(self, data, max_list_items=5):
        if isinstance(data, dict):
            new_data = {}
            for k, v in data.items():
                if k in ['icon', 'favicon', 'html', 'screenshot', 'raw_response', 'response_headers']: continue
                new_data[k] = self._prune_data(v, max_list_items)
            return new_data
        elif isinstance(data, list):
            return [self._prune_data(i, max_list_items) for i in data[:max_list_items]]
        else:
            return data

    def _extract_key_intel(self, raw_data):
        summary = {}
        if 'virustotal' in raw_data and isinstance(raw_data['virustotal'], dict):
            vt = raw_data['virustotal']
            attrs = vt.get('attributes', {})
            rels = vt.get('relationships', {})
            summary['virustotal'] = {
                'stats': attrs.get('last_analysis_stats'),
                'tags': attrs.get('tags'),
                'as_owner': attrs.get('as_owner'),
                'passive_dns': [r.get('attributes', {}).get('host_name') for r in rels.get('resolutions', {}).get('data', [])[:5]]
            }
        if 'urlscan' in raw_data and isinstance(raw_data['urlscan'], dict):
            us = raw_data['urlscan']
            summary['urlscan'] = {
                'verdict': us.get('verdict', {}).get('overall'),
                'target': us.get('task', {}).get('url')
            }
        if 'abuseipdb' in raw_data and isinstance(raw_data['abuseipdb'], dict):
            ab = raw_data['abuseipdb']
            summary['abuseipdb'] = {'score': ab.get('abuseConfidenceScore'), 'usage': ab.get('usageType')}
        return summary

    async def analyze_batch(self, items):
        if not items: return []
        chunk_size = 10
        results = []
        
        system_instruction = """
        You are an expert CTI Analyst.
        Task: Analyze cyber news items.
        OUTPUT RULES:
        1. IF Source is 'INCD' -> Hebrew.
        2. IF Source is 'DeepWeb' -> Check Title/Summary for dates. If date is older than 30 days, prefix Title with [ARCHIVE].
        3. GENERAL -> JSON: {"items": [{"id": 0, "category": "...", "severity": "...", "title": "...", "summary": "..."}]}
        """
        
        for i in range(0, len(items), chunk_size):
            chunk = items[i:i+chunk_size]
            batch_lines = []
            for idx, x in enumerate(chunk):
                batch_lines.append(f"ID:{idx}|Src:{x['source']}|Original:{x['title']} - {x['summary'][:400]}")

            prompt = f"{system_instruction}\nRaw Data:\n{'\n'.join(batch_lines)}"
            res = await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=True)
            chunk_map = {}
            try:
                data = json.loads(res)
                for item in data.get("items", []): chunk_map[item.get('id')] = item
            except: pass
            
            for j in range(len(chunk)):
                ai = chunk_map.get(j, {})
                results.append({
                    "category": ai.get('category', 'News'), 
                    "severity": ai.get('severity', 'Medium'), 
                    "title": ai.get('title', chunk[j]['title']),
                    "summary": ai.get('summary', chunk[j]['summary'])
                })
        return results

    async def analyze_single_ioc(self, ioc, ioc_type, data):
        # 1. Extract Technical Data
        lean_data = self._extract_key_intel(data)
        
        # 2. RUN ACTIVE DEEP WEB SCAN (OSINT) - This makes the AI "Smart"
        scanner = DeepWebScanner()
        osint_hits = scanner.scan_ioc(ioc, limit=4)
        
        # 3. Construct Smart Prompt
        prompt = f"""
        You are a Senior Cyber Threat Intelligence Analyst.
        Your goal: Provide an accurate operational verdict for this IOC by CROSS-REFERENCING Technical Data with Open Source Intelligence (OSINT).

        TARGET: {ioc} ({ioc_type})

        --- DATA SOURCE 1: TECHNICAL TELEMETRY ---
        {json.dumps(lean_data)}

        --- DATA SOURCE 2: REAL-TIME WEB SEARCH (OSINT) ---
        {json.dumps(osint_hits)}

        --- ANALYSIS INSTRUCTIONS ---
        1. **LOOK FOR LEGITIMACY**: Read the OSINT snippets. Does this look like an official website of a government, bank, infrastructure (e.g., 'kvish6', 'post', 'bank')? 
           - IF YES + Technical Score is Low/Undetected -> VERDICT IS CLEAN (False Positive).
           - Do NOT assume "Undetected" means "Suspicious". "Undetected" on a legitimate business site means SAFE.

        2. **LOOK FOR THREATS**: Do the OSINT results mention "malware", "phishing", "C2", or "breach" linked to this specific domain?
           - IF YES -> VERDICT IS MALICIOUS.

        3. **VERDICT**:
           - Clean: Official business/gov site with no malware indications.
           - Malicious: Clear evidence of hostility.
           - Suspicious: Ambiguous data (e.g., new domain, no content, but no detections).

        Output Format (Markdown):
        ### 🛡️ Operational Verdict
        * **Verdict**: [Malicious / Suspicious / Clean]
        * **Confidence**: [High / Medium / Low]
        * **Reasoning**: <Explain using the OSINT findings. E.g., "Identified as official site of X via web search, confirmed by 0 VT detections.">

        ### 🏢 Enterprise Defense Playbook
        * **Action**: <Block / Monitor / Whitelist>
        * **Network**: <Specific rule>
        * **Endpoint**: <Specific instruction>

        ### 🔬 Intelligence Context
        * Summarize the Web Search findings.
        """
        
        res = await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)
        if "Error" in res:
            return await query_groq_api(self.key, prompt, model="llama-3.1-8b-instant", json_mode=False)
        return res

    async def generate_hunting_queries(self, actor):
        prompt = f"Generate Hunting Queries for Actor: {actor['name']}..."
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
                endpoint = "ip_addresses" if ioc_type == "ip" else "domains" if ioc_type == "domain" else "files"
                endpoint = f"{endpoint}/{ioc}"
            
            params = {}
            if ioc_type in ['file', 'domain', 'ip', 'url']:
                params['relationships'] = 'contacted_urls,contacted_ips,contacted_domains,resolutions'
            
            res = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}", headers={"x-apikey": self.vt_key}, params=params, timeout=15)
            if res.status_code == 200: return res.json().get('data', {})
            return None
        except: return None

    def query_urlscan(self, ioc):
        if not self.urlscan_key: return None
        try:
            res = requests.get(f"https://urlscan.io/api/v1/search/?q={ioc}", headers={"API-Key": self.urlscan_key}, timeout=15)
            data = res.json()
            if data.get('results'):
                return requests.get(f"https://urlscan.io/api/v1/result/{data['results'][0]['_id']}/", headers={"API-Key": self.urlscan_key}, timeout=15).json()
            return None
        except: return None

    def query_abuseipdb(self, ip):
        if not self.abuse_key: return None
        try:
            return requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': self.abuse_key, 'Accept': 'application/json'}, params={'ipAddress': ip}, timeout=10).json().get('data', {})
        except: return None

class AnalystToolkit:
    @staticmethod
    def get_tools():
        return {
            "Analysis": [{"name": "CyberChef", "url": "https://gchq.github.io/CyberChef/", "desc": "Decoding tool"}],
            "Lookup": [{"name": "VirusTotal", "url": "https://www.virustotal.com/", "desc": "File/URL Analysis"}]
        }

class APTSheetCollector:
    def fetch_threats(self): 
        return [
            {"name": "MuddyWater", "origin": "Iran", "target": "Israel", "type": "Espionage", "tools": "PowerShell, ScreenConnect", "keywords": ["muddywater"], "mitre": "T1059", "malpedia": "#"},
            {"name": "OilRig (APT34)", "origin": "Iran", "target": "Israel", "type": "Espionage", "tools": "DNS Tunneling", "keywords": ["oilrig"], "mitre": "T1071", "malpedia": "#"},
            {"name": "Imperial Kitten", "origin": "Iran", "target": "Israel", "type": "Espionage", "tools": "IMAPLoader", "keywords": ["imperial kitten"], "mitre": "T1566", "malpedia": "#"},
            {"name": "Agonizing Serpens", "origin": "Iran", "target": "Israel", "type": "Destructive", "tools": "Wipers", "keywords": ["agonizing serpens"], "mitre": "T1485", "malpedia": "#"}
        ]

class CTICollector:
    SOURCES = [
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "HackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        {"name": "Malpedia", "url": "https://malpedia.caad.fkie.fraunhofer.de/feeds/rss/latest", "type": "rss"},
        {"name": "INCD", "url": "https://www.gov.il/he/rss/news_list", "type": "rss"},
        {"name": "INCD", "url": "https://t.me/s/Israel_Cyber", "type": "telegram"}
    ]

    async def fetch_item(self, session, source):
        items = []
        try:
            async with session.get(source['url'], headers=HEADERS, timeout=25) as resp:
                if resp.status != 200: return []
                content = await resp.text()
                now = datetime.datetime.now(IL_TZ)
                
                is_incd = source['name'] == 'INCD'
                
                if source['type'] == 'rss':
                    feed = feedparser.parse(content)
                    entries = feed.entries[:4] if is_incd else feed.entries[:10]
                    for entry in entries:
                        pub_date = now
                        if hasattr(entry, 'published_parsed') and entry.published_parsed:
                            pub_date = datetime.datetime(*entry.published_parsed[:6]).replace(tzinfo=pytz.utc).astimezone(IL_TZ)
                        
                        if not is_incd and (now - pub_date).total_seconds() > (48 * 3600): continue
                        if _is_url_processed(entry.link): continue
                        
                        sum_text = BeautifulSoup(getattr(entry, 'summary', ''), "html.parser").get_text()[:600]
                        items.append({"title": entry.title, "url": entry.link, "date": pub_date.isoformat(), "source": source['name'], "summary": sum_text})
                
                # ... (Additional parsers would go here)
        except: pass
        return items

    async def get_all_data(self):
        async with aiohttp.ClientSession() as session:
            # 1. Fetch Standard Feeds
            tasks = [self.fetch_item(session, s) for s in self.SOURCES]
            results = await asyncio.gather(*tasks)
            all_items = [i for sub in results for i in sub]
            
            # 2. AUTOMATED DEEP WEB SCAN FOR ALL ACTORS
            # Runs automatically on every refresh!
            scanner = DeepWebScanner()
            actors = APTSheetCollector().fetch_threats()
            for actor in actors:
                # Limit to 2 results per actor per run
                hits = scanner.scan_actor(actor['name'], limit=2) 
                if hits: all_items.extend(hits)
            
            return all_items

def save_reports(raw, analyzed):
    conn = sqlite3.connect(DB_NAME)
    c, cnt = conn.cursor(), 0
    for i, item in enumerate(raw):
        if i < len(analyzed):
            a = analyzed[i]
            try:
                c.execute("INSERT OR IGNORE INTO intel_reports (timestamp,published_at,source,url,title,category,severity,summary) VALUES (?,?,?,?,?,?,?,?)",
                    (datetime.datetime.now(IL_TZ).isoformat(), item['date'], item['source'], item['url'], a['title'], a['category'], a['severity'], a['summary']))
                if c.rowcount > 0: cnt += 1
            except: pass
    conn.commit()
    conn.close()
    return cnt
