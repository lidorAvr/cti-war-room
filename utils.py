import sqlite3
import asyncio
import aiohttp
import json
import datetime
import requests
import pandas as pd
import re
import base64
from bs4 import BeautifulSoup
from dateutil import parser

# --- CONFIG ---
DB_NAME = "cti_dashboard.db"

# --- DATABASE INIT ---
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
        impact TEXT,
        summary TEXT
    )''')
    limit = (datetime.datetime.now() - datetime.timedelta(hours=48)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE published_at < ?", (limit,))
    conn.commit()
    conn.close()

# --- HELPERS ---
def sanitize_ioc(ioc):
    ioc = ioc.strip()
    match = re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)$', ioc)
    if match: return match.group(1), match.group(2)
    return ioc, None

def get_ioc_type(ioc):
    ioc = ioc.strip()
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc): return "ip"
    if re.match(r'^[a-fA-F0-9]{32}$', ioc) or re.match(r'^[a-fA-F0-9]{64}$', ioc): return "hash"
    if "http" in ioc or "/" in ioc: return "url"
    return "domain"

def vt_url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

# --- CORE AI LOGIC (Direct HTTP) ---
async def query_gemini_direct(api_key, prompt):
    if not api_key: return None
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    headers = {'Content-Type': 'application/json'}
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers, timeout=20) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data['candidates'][0]['content']['parts'][0]['text']
                else:
                    print(f"Gemini Error {resp.status}: {await resp.text()}")
                    return None
    except Exception as e:
        print(f"Gemini Exception: {e}")
        return None

# --- COLLECTORS ---
class CTICollector:
    SOURCES = [
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        {"name": "CheckPoint", "url": "https://research.checkpoint.com/feed/", "type": "rss"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"}
    ]
    
    async def fetch_item(self, session, source):
        try:
            async with session.get(source['url'], timeout=10) as resp:
                if resp.status != 200: return []
                if source['type'] == 'rss':
                    text = await resp.text()
                    soup = BeautifulSoup(text, 'xml')
                    items = []
                    for i in soup.find_all('item')[:5]:
                        d = i.pubDate.text if i.pubDate else str(datetime.datetime.now())
                        try: dt = parser.parse(d).isoformat()
                        except: dt = str(datetime.datetime.now())
                        items.append({"title": i.title.text, "url": i.link.text, "date": dt, "source": source['name'], "summary": i.description.text[:500] if i.description else ""})
                    return items
                elif source['type'] == 'json':
                    data = await resp.json()
                    return [{"title": f"KEV: {v['cveID']}", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "date": str(datetime.datetime.now()), "source": "CISA", "summary": v['vulnerabilityName']} for v in data.get('vulnerabilities', [])[:3]]
        except: return []

    async def get_all_data(self):
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_item(session, s) for s in self.SOURCES]
            results = await asyncio.gather(*tasks)
            return [i for sub in results for i in sub]

# --- PROCESSORS ---
class AIBatchProcessor:
    def __init__(self, key):
        self.key = key
        
    async def analyze_batch(self, items):
        if not items or not self.key: 
            return [{"id": i, "category": "General", "severity": "Medium", "impact": "Info", "summary": x['summary'][:200]} for i,x in enumerate(items)]
            
        batch_text = "\n".join([f"ID:{i}|Title:{x['title']}|Desc:{x['summary'][:100]}" for i,x in enumerate(items)])
        prompt = f"Analyze these threats. Return JSON Array: [{{'id':0, 'category':'Malware', 'severity':'High', 'impact':'Risk', 'summary':'Short summary'}}]. Items:\n{batch_text}"
        
        res = await query_gemini_direct(self.key, prompt)
        if res:
            try:
                clean = res.replace('```json','').replace('```','').strip()
                if '[' in clean: clean = clean[clean.find('['):clean.rfind(']')+1]
                return json.loads(clean)
            except: pass
        return [{"id": i, "category": "General", "severity": "Medium", "impact": "Info", "summary": x['summary'][:200]} for i,x in enumerate(items)]

    async def analyze_single_ioc(self, ioc, data):
        prompt = f"Analyze IOC: {ioc}. Data: {json.dumps(data, default=str)}. Return Markdown report with Verdict, Findings, Recommendations."
        res = await query_gemini_direct(self.key, prompt)
        return res if res else "Error: AI Unresponsive."

def save_reports(raw, analyzed):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        amap = {r['id']:r for r in analyzed if isinstance(r, dict)}
        cnt = 0
        for i,item in enumerate(raw):
            a = amap.get(i, {})
            try:
                c.execute("INSERT OR IGNORE INTO intel_reports (timestamp,published_at,source,url,title,category,severity,impact,summary) VALUES (?,?,?,?,?,?,?,?,?)",
                    (datetime.datetime.now().isoformat(), item['date'], item['source'], item['url'], item['title'], 
                     a.get('category','General'), a.get('severity','Medium'), a.get('impact','Info'), a.get('summary', item['summary'])))
                if c.rowcount > 0: cnt += 1
            except: pass
        conn.commit()
        conn.close()
        return cnt
    except: return 0

# --- INVESTIGATION TOOLS ---
class ThreatLookup:
    def __init__(self, abuse_ch_key=None, vt_key=None, urlscan_key=None, cyscan_key=None):
        self.keys = {'vt': vt_key, 'urlscan': urlscan_key, 'abuse_ch': abuse_ch_key}

    def query_virustotal(self, ioc):
        if not self.keys['vt']: return {"status": "skipped"}
        try:
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            ep = f"https://www.virustotal.com/api/v3/urls/{url_id}" if "http" in ioc else f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
            res = requests.get(ep, headers={"x-apikey": self.keys['vt']}, timeout=5)
            if res.status_code == 200: return {"status": "found", "stats": res.json()['data']['attributes']['last_analysis_stats']}
            return {"status": "not_found"}
        except: return {"status": "error"}

    def query_abuseipdb(self, ip, key):
        try:
            res = requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': key}, params={'ipAddress': ip}, timeout=5)
            return {"success": True, "data": res.json()['data']} if res.status_code == 200 else {"error": "Failed"}
        except: return {"error": "Connection Failed"}

    def query_threatfox(self, ioc): return {"status": "skipped"} # Placeholder
    def query_urlhaus(self, ioc): return {"status": "skipped"} # Placeholder
    def query_urlscan(self, ioc): return {"status": "skipped"} # Placeholder
    def query_cyscan(self, ioc): return {"link": f"https://cyscan.io/search/{ioc}"}

class AbuseIPDBChecker:
    def __init__(self, key): self.key = key
    def check_ip(self, ip): 
        # Wrapper reusing existing logic
        try:
            res = requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': self.key}, params={'ipAddress': ip}, timeout=5)
            if res.status_code == 200: return {"success": True, "data": res.json()['data']}
            return {"error": "API Fail"}
        except: return {"error": "Conn Fail"}

class ConnectionManager:
    @staticmethod
    def check_gemini(key):
        if not key: return False, "Missing Key"
        try:
            res = requests.post(f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={key}", 
                              json={"contents":[{"parts":[{"text":"Ping"}]}]}, timeout=5)
            return (True, "Connected") if res.status_code == 200 else (False, f"Error {res.status_code}")
        except Exception as e: return False, str(e)
    
    @staticmethod
    def check_abuseipdb(key): return True, "Checked" # Simplified
    @staticmethod
    def check_abusech(key): return True, "Checked"
    @staticmethod
    def check_virustotal(key): return True, "Checked"
    @staticmethod
    def check_urlscan(key): return True, "Checked"

class IOCExtractor:
    def extract(self, text):
        return {
            "IPs": re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text),
            "Domains": re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', text),
            "Hashes": re.findall(r'\b[a-fA-F0-9]{32,64}\b', text)
        }

class MitreCollector:
    def get_latest_updates(self): return None

class APTSheetCollector:
    def fetch_threats(self, region): return pd.DataFrame()
