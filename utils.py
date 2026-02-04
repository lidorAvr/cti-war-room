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
        impact TEXT,
        summary TEXT
    )''')
    
    # Auto-cleanup: Delete reports older than 48 hours
    limit = (datetime.datetime.now() - datetime.timedelta(hours=48)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE published_at < ?", (limit,))
    conn.commit()
    conn.close()

# --- HELPERS ---
def get_ioc_type(ioc):
    ioc = ioc.strip()
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc): return "ip"
    if "http" in ioc: return "url"
    if len(ioc) in [32, 40, 64]: return "hash"
    return "domain"

# --- AI LOGIC (Auto-Discovery Mode) ---
async def get_valid_model_name(api_key, session):
    """Asks Google which models are available for this specific API Key"""
    list_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    try:
        async with session.get(list_url) as resp:
            if resp.status != 200: return None
            data = await resp.json()
            # Find the first model that supports content generation
            for model in data.get('models', []):
                if 'generateContent' in model.get('supportedGenerationMethods', []):
                    return model['name']
    except: return None
    return "models/gemini-1.5-flash" # Fallback

async def query_gemini_auto(api_key, prompt):
    if not api_key: return None
    async with aiohttp.ClientSession() as session:
        # 1. Discover Model
        model_name = await get_valid_model_name(api_key, session)
        if not model_name: return "Error: No valid models found for this API Key."
        
        if not model_name.startswith("models/"): model_name = f"models/{model_name}"
            
        # 2. Generate Content
        url = f"https://generativelanguage.googleapis.com/v1beta/{model_name}:generateContent?key={api_key}"
        headers = {'Content-Type': 'application/json'}
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        
        try:
            async with session.post(url, json=payload, headers=headers, timeout=30) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data['candidates'][0]['content']['parts'][0]['text']
                else:
                    return f"AI Error {resp.status}: {await resp.text()}"
        except Exception as e:
            return f"Connection Error: {e}"

# --- HEALTH CHECKS ---
class ConnectionManager:
    @staticmethod
    def check_gemini(key):
        if not key: return False, "Missing Key"
        try:
            # Quick Ping
            res = requests.post(f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={key}", 
                              json={"contents":[{"parts":[{"text":"Ping"}]}]}, timeout=5)
            if res.status_code == 200: return True, "✅ Connected!"
            return False, f"❌ Error {res.status_code}"
        except: return False, "❌ Connection Failed"
    
    @staticmethod
    def check_abuseipdb(key):
        try: return (True, "Connected") if requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': key}, params={'ipAddress':'8.8.8.8'}, timeout=5).status_code == 200 else (False, "Error")
        except: return False, "Error"
    
    @staticmethod
    def check_virustotal(key):
        try: return (True, "Connected") if requests.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", headers={"x-apikey": key}, timeout=5).status_code == 200 else (False, "Error")
        except: return False, "Error"

# --- COLLECTORS (Data Fetching) ---
class CTICollector:
    SOURCES = [
        {"name": "CheckPoint", "url": "https://research.checkpoint.com/feed/", "type": "rss"},
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"}
    ]
    
    async def fetch_item(self, session, source):
        try:
            async with session.get(source['url'], timeout=15) as resp:
                if resp.status != 200: return []
                
                if source['type'] == 'rss':
                    text = await resp.text()
                    soup = BeautifulSoup(text, 'xml')
                    items = []
                    for i in soup.find_all('item')[:7]:
                        # Date Parsing
                        pub_date = i.pubDate.text if i.pubDate else str(datetime.datetime.now())
                        try:
                            dt_obj = parser.parse(pub_date)
                            dt_iso = dt_obj.isoformat()
                        except:
                            dt_iso = datetime.datetime.now().isoformat()
                        
                        desc = i.description.text if i.description else ""
                        soup_desc = BeautifulSoup(desc, "html.parser")
                        items.append({"title": i.title.text, "url": i.link.text, "date": dt_iso, "source": source['name'], "summary": soup_desc.get_text()[:600]})
                    return items
                    
                elif source['type'] == 'json':
                    data = await resp.json()
                    return [{"title": f"KEV: {v['cveID']} - {v['vulnerabilityName']}", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", 
                             "date": f"{v.get('dateAdded')}T00:00:00", "source": "CISA", "summary": v['shortDescription']} for v in data.get('vulnerabilities', [])[:5]]
        except Exception as e: 
            return []

    async def get_all_data(self):
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_item(session, s) for s in self.SOURCES]
            results = await asyncio.gather(*tasks)
            return [i for sub in results for i in sub]

# --- AI PROCESSOR ---
class AIBatchProcessor:
    def __init__(self, key):
        self.key = key
        
    async def analyze_batch(self, items):
        if not items: return []
        if not self.key: 
            return [{"id": i, "category": "General", "severity": "Medium", "impact": "Info", "summary": x['summary'][:200]} for i,x in enumerate(items)]
            
        batch_text = "\n".join([f"ID:{i}|Src:{x['source']}|Title:{x['title']}|Desc:{x['summary'][:150]}" for i,x in enumerate(items)])
        prompt = f"""
        Act as a Cyber Intelligence Analyst. Analyze these items.
        
        Rules:
        1. 'Israel'/'Iran'/'Hamas' in text -> Category 'Israel Focus'.
        2. 'CISA' or 'CVE' -> Severity 'Critical'.
        3. Marketing/Sales -> Category 'General', Severity 'Low'.
        
        Output JSON Array ONLY:
        [
          {{"id": 0, "category": "Malware/Phishing/Vulnerability/Israel Focus", "severity": "Critical/High/Medium/Low", "impact": "Short impact desc", "summary": "One sentence summary."}}
        ]
        
        Items:
        {batch_text}
        """
        
        res = await query_gemini_auto(self.key, prompt)
        if res:
            try:
                clean = res.replace('```json','').replace('```','').strip()
                if '[' in clean: clean = clean[clean.find('['):clean.rfind(']')+1]
                return json.loads(clean)
            except: pass
            
        return [{"id": i, "category": "General", "severity": "Medium", "impact": "AI Error", "summary": x['summary'][:200]} for i,x in enumerate(items)]

    async def analyze_single_ioc(self, ioc, data):
        prompt = f"""
        **SOC Analyst Request:**
        Investigate this IOC: {ioc}
        
        **Collected Intelligence Data:**
        {json.dumps(data, indent=2, default=str)}
        
        **Task:**
        Provide a professional markdown report.
        1. **Verdict:** (Malicious / Suspicious / Benign) with Confidence Level.
        2. **Summary:** Why is this good/bad?
        3. **Key Evidence:** Bullet points from the data (e.g. VirusTotal score, ISP, Country).
        4. **Recommended Action:** (Block, Monitor, Ignore).
        """
        return await query_gemini_auto(self.key, prompt)

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
                     a.get('category','General'), a.get('severity','Medium'), a.get('impact','Unknown'), a.get('summary', item['summary'])))
                if c.rowcount > 0: cnt += 1
            except: pass
        conn.commit()
        conn.close()
        return cnt
    except: return 0

# --- TOOLS ---
class ThreatLookup:
    def __init__(self, abuse_ch_key=None, vt_key=None, urlscan_key=None, cyscan_key=None):
        self.keys = {'vt': vt_key, 'urlscan': urlscan_key, 'abuse_ch': abuse_ch_key}

    def query_virustotal(self, ioc):
        if not self.keys['vt']: return {"status": "skipped", "msg": "No API Key"}
        try:
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            ep = f"https://www.virustotal.com/api/v3/urls/{url_id}" if "http" in ioc else f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
            res = requests.get(ep, headers={"x-apikey": self.keys['vt']}, timeout=10)
            if res.status_code == 200: 
                data = res.json()['data']['attributes']
                return {"status": "found", "stats": data['last_analysis_stats'], "reputation": data.get('reputation', 0)}
            return {"status": "not_found"}
        except: return {"status": "error"}

    def query_abuseipdb(self, ip, key):
        if not key: return {"error": "Missing Key"}
        try:
            res = requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': key}, params={'ipAddress': ip}, timeout=5)
            return {"success": True, "data": res.json()['data']} if res.status_code == 200 else {"error": "Failed"}
        except: return {"error": "Conn Fail"}

    def query_threatfox(self, ioc):
        try:
            res = requests.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_ioc", "search_term": ioc}, timeout=10)
            data = res.json()
            if data.get("query_status") == "ok": return {"status": "found", "data": data.get("data", [])}
            return {"status": "not_found"}
        except: return {"status": "error"}

    def query_urlhaus(self, ioc):
        try:
            res = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={'url': ioc}, timeout=10)
            if res.status_code == 200 and res.json().get("query_status") == "ok": return {"status": "found", "data": res.json()}
            return {"status": "not_found"}
        except: return {"status": "error"}

    def query_urlscan(self, ioc):
        if not self.keys['urlscan']: return {"status": "skipped"}
        try:
            res = requests.get(f"https://urlscan.io/api/v1/search/?q={ioc}", headers={"API-Key": self.keys['urlscan']}, timeout=10)
            if res.status_code == 200 and res.json().get("results"):
                return {"status": "found", "screenshot": res.json()["results"][0].get("screenshot"), "verdict": res.json()["results"][0].get("verdict")}
            return {"status": "not_found"}
        except: return {"status": "error"}

class AbuseIPDBChecker:
    def __init__(self, key): self.key = key
    def check_ip(self, ip): 
        tl = ThreatLookup()
        return tl.query_abuseipdb(ip, self.key)

class IOCExtractor:
    def extract(self, text):
        return {
            "IPs": list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text))),
            "Domains": list(set(re.findall(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', text))),
            "Hashes": list(set(re.findall(r'\b[a-fA-F0-9]{32}\b', text) + re.findall(r'\b[a-fA-F0-9]{64}\b', text)))
        }

class MitreCollector:
    def get_latest_updates(self):
        try:
            res = requests.get("https://attack.mitre.org/resources/updates/", timeout=5)
            soup = BeautifulSoup(res.text, 'html.parser')
            h2 = soup.find('h2')
            if h2: return {"title": h2.text.strip(), "url": "https://attack.mitre.org"}
        except: return None

class APTSheetCollector:
    def fetch_threats(self, region):
        try:
            url = "https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/export?format=csv&gid=1864660085"
            return pd.read_csv(url).head(30)
        except: return pd.DataFrame()
