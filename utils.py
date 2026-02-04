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

DB_NAME = "cti_dashboard.db"

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

# --- Helpers ---
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

# --- CORE: Direct HTTP Request to Google (Bypassing all libraries) ---
async def query_gemini_http(api_key, prompt):
    """
    Tries multiple model endpoints directly via HTTP to bypass library version hell.
    """
    # List of endpoints to try in order.
    # We try both 'models/' prefix and specific versions.
    endpoints = [
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-pro:generateContent",
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent"
    ]
    
    headers = {'Content-Type': 'application/json'}
    payload = {
        "contents": [{
            "parts": [{"text": prompt}]
        }]
    }
    
    async with aiohttp.ClientSession() as session:
        for url in endpoints:
            target_url = f"{url}?key={api_key}"
            try:
                # print(f"DEBUG: Trying {url.split('/models/')[1]}...")
                async with session.post(target_url, headers=headers, json=payload, timeout=20) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        try:
                            # Extract text safely
                            return data['candidates'][0]['content']['parts'][0]['text']
                        except:
                            continue # Malformed response, try next
                    elif resp.status == 429:
                        return None # Quota exceeded, stop trying
                    # If 404 or other error, loop to next model
            except:
                continue
                
    return None

# --- Health Check Manager ---
class ConnectionManager:
    @staticmethod
    def check_gemini(key):
        if not key: return False, "Missing Key"
        
        # Test connection synchronously
        models_to_test = [
            "gemini-1.5-flash",
            "gemini-1.5-pro",
            "gemini-pro"
        ]
        
        for m in models_to_test:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent?key={key}"
            try:
                res = requests.post(url, json={"contents": [{"parts": [{"text": "Ping"}]}]}, timeout=5)
                if res.status_code == 200: return True, f"Connected ({m})"
                if res.status_code == 429: return False, "Quota Exceeded (429)"
            except: pass
            
        return False, "Failed to connect to ANY Gemini model (Check Key Type)"

    @staticmethod
    def check_abuseipdb(key):
        if not key: return False, "Missing Key"
        try:
            res = requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': key}, params={'ipAddress': '8.8.8.8'}, timeout=5)
            if res.status_code == 200: return True, "Connected"
            return False, f"HTTP {res.status_code}"
        except: return False, "Error"

    @staticmethod
    def check_abusech(key):
        try:
            res = requests.get("https://urlhaus-api.abuse.ch/v1/tag/malware/", timeout=10)
            if res.status_code == 200: return True, "Connected"
            return False, f"HTTP {res.status_code}"
        except: return False, "Error"

    @staticmethod
    def check_virustotal(key):
        if not key: return False, "Missing Key"
        try:
            res = requests.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", headers={"x-apikey": key}, timeout=5)
            if res.status_code == 200: return True, "Connected"
            return False, f"HTTP {res.status_code}"
        except: return False, "Error"

    @staticmethod
    def check_urlscan(key):
        if not key: return False, "Missing Key"
        try:
            res = requests.get("https://urlscan.io/api/v1/search/?q=domain:google.com", headers={"API-Key": key}, timeout=5)
            if res.status_code == 200: return True, "Connected"
            return False, f"HTTP {res.status_code}"
        except: return False, "Error"

# --- Threat Lookup ---
class ThreatLookup:
    def __init__(self, abuse_ch_key=None, vt_key=None, urlscan_key=None, cyscan_key=None):
        self.abuse_ch_key = abuse_ch_key
        self.vt_key = vt_key
        self.urlscan_key = urlscan_key
        self.cyscan_key = cyscan_key
        self.headers = {'User-Agent': 'SOC-Analyst-Bot'}

    def query_threatfox(self, ioc):
        try:
            res = requests.post("https://threatfox-api.abuse.ch/api/v1/", 
                              json={"query": "search_ioc", "search_term": ioc}, timeout=10)
            data = res.json()
            if data.get("query_status") == "ok": return {"status": "found", "data": data.get("data", [])}
            return {"status": "not_found"}
        except: return {"status": "error"}

    def query_urlhaus(self, ioc):
        try:
            res = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={'url': ioc}, timeout=10)
            if res.status_code == 200 and res.json().get("query_status") == "ok":
                return {"status": "found", "data": res.json()}
            return {"status": "not_found"}
        except: return {"status": "error"}

    def query_virustotal(self, ioc):
        if not self.vt_key: return {"status": "skipped"}
        try:
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}" if "http" in ioc else f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
            res = requests.get(endpoint, headers={"x-apikey": self.vt_key}, timeout=10)
            if res.status_code == 200:
                return {"status": "found", "stats": res.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})}
            return {"status": "not_found"}
        except: return {"status": "error"}

    def query_urlscan(self, ioc):
        if not self.urlscan_key: return {"status": "skipped"}
        try:
            res = requests.get(f"https://urlscan.io/api/v1/search/?q={ioc}", headers={"API-Key": self.urlscan_key}, timeout=10)
            if res.status_code == 200 and res.json().get("results"):
                return {"status": "found", "screenshot": res.json()["results"][0].get("screenshot")}
            return {"status": "not_found"}
        except: return {"status": "error"}

    def query_cyscan(self, ioc):
        return {"link": f"https://cyscan.io/search/{ioc}"}

# --- AI Processors (USING HTTP WRAPPER) ---
class AIBatchProcessor:
    def __init__(self, key):
        self.key = key
        
    async def analyze_batch(self, items):
        if not items: return []
        fallback = [{"id": i, "category": "General", "severity": "Medium", "impact": "Info", "summary": x['summary'][:150]} for i,x in enumerate(items)]
        
        if not self.key: return fallback

        batch_text = "\n".join([f"ID:{i}|Title:{x['title']}|Desc:{x['summary'][:100]}" for i,x in enumerate(items)])
        prompt = f"""
        Analyze these cyber threats.
        Input: ID:0|Title:..|Desc:..
        
        Output JSON Array ONLY:
        [{{"id":0, "category":"Malware/Phishing/General", "severity":"Critical/High/Medium", "impact":"Short impact", "summary":"One sentence"}}]
        
        Items:
        {batch_text}
        """
        
        result = await query_gemini_http(self.key, prompt)
        if result:
            try:
                clean = result.replace('```json','').replace('```','').strip()
                if '[' in clean: clean = clean[clean.find('['):clean.rfind(']')+1]
                return json.loads(clean)
            except: pass
            
        return fallback

    async def analyze_single_ioc(self, ioc, data):
        if not self.key: return "⚠️ Missing API Key"
        
        prompt = f"""
        Act as a SOC Analyst. Analyze IOC: {ioc}.
        Data: {json.dumps(data, default=str)}
        
        Output Markdown:
        ## Verdict: [Malicious/Safe]
        * Findings
        * Action
        """
        
        res = await query_gemini_http(self.key, prompt)
        return res if res else "❌ Error: AI Unresponsive (Check Key/Quota)"

def save_reports(raw, analyzed):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        amap = {r['id']:r for r in analyzed if isinstance(r, dict)}
        cnt = 0
        for i,item in enumerate(raw):
            try:
                a = amap.get(i, {})
                c.execute("INSERT OR IGNORE INTO intel_reports (timestamp,published_at,source,url,title,category,severity,impact,summary) VALUES (?,?,?,?,?,?,?,?,?)",
                    (datetime.datetime.now().isoformat(), item['date'], item['source'], item['url'], item['title'], 
                     a.get('category','General'), a.get('severity','Medium'), a.get('impact','Info'), a.get('summary', item['summary'])))
                if c.rowcount > 0: cnt += 1
            except: pass
        conn.commit()
        conn.close()
        return cnt
    except: return 0

# --- Required Classes for app.py imports ---
class MitreCollector:
    def get_latest_updates(self): return None
class APTSheetCollector:
    def fetch_threats(self, r): return pd.DataFrame()
class AbuseIPDBChecker: # Kept for backward compatibility if app.py calls it directly
    def __init__(self, key): self.key = key
    def check_ip(self, ip): return ConnectionManager.check_abuseipdb(self.key)
