import sqlite3
import asyncio
import aiohttp
import json
import datetime
import requests
import pandas as pd
import re
import base64
import pytz # Added for Israel Time
from bs4 import BeautifulSoup
from dateutil import parser

DB_NAME = "cti_dashboard.db"
# Define Israel Timezone
IL_TZ = pytz.timezone('Asia/Jerusalem')

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
    limit = (datetime.datetime.now(IL_TZ) - datetime.timedelta(hours=48)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE published_at < ?", (limit,))
    conn.commit()
    conn.close()

# --- HELPERS ---
def get_current_il_time():
    return datetime.datetime.now(IL_TZ).strftime("%d/%m/%Y %H:%M")

def get_ioc_type(ioc):
    ioc = ioc.strip()
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc): return "ip"
    if "http" in ioc: return "url"
    if len(ioc) in [32, 40, 64]: return "hash"
    return "domain"

# --- AI LOGIC ---
async def get_valid_model_name(api_key, session):
    """Asks Google which models are available"""
    list_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    try:
        async with session.get(list_url) as resp:
            if resp.status != 200: return None
            data = await resp.json()
            for model in data.get('models', []):
                if 'generateContent' in model.get('supportedGenerationMethods', []):
                    return model['name']
    except: return None
    return "models/gemini-1.5-flash"

async def query_gemini_auto(api_key, prompt):
    if not api_key: return None
    async with aiohttp.ClientSession() as session:
        model_name = await get_valid_model_name(api_key, session)
        if not model_name: return "Error: Check API Key scope."
        
        if not model_name.startswith("models/"): model_name = f"models/{model_name}"
            
        url = f"https://generativelanguage.googleapis.com/v1beta/{model_name}:generateContent?key={api_key}"
        headers = {'Content-Type': 'application/json'}
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        
        try:
            async with session.post(url, json=payload, headers=headers, timeout=30) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data['candidates'][0]['content']['parts'][0]['text']
                else:
                    return f"AI Error {resp.status}"
        except Exception as e:
            return f"Connection Error: {e}"

# --- HEALTH CHECKS ---
class ConnectionManager:
    @staticmethod
    def check_gemini(key):
        if not key: return False, "Missing Key"
        try:
            res = requests.post(f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={key}", 
                              json={"contents":[{"parts":[{"text":"Ping"}]}]}, timeout=5)
            if res.status_code == 200: return True, "Connected"
            return False, f"Error {res.status_code}"
        except: return False, "Connection Failed"

# --- COLLECTORS ---
class CTICollector:
    # Added MITRE RSS and removed specific APT collector to unify feed
    SOURCES = [
        {"name": "CheckPoint", "url": "https://research.checkpoint.com/feed/", "type": "rss"},
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        {"name": "MITRE ATT&CK", "url": "https://attack.mitre.org/atom.xml", "type": "rss"} 
    ]
    
    async def fetch_item(self, session, source):
        try:
            async with session.get(source['url'], timeout=15) as resp:
                if resp.status != 200: return []
                
                if source['type'] == 'rss':
                    text = await resp.text()
                    soup = BeautifulSoup(text, 'xml')
                    items = []
                    # Fetching items
                    entries = soup.find_all('entry') # Atom support
                    if not entries: entries = soup.find_all('item') # RSS support

                    for i in entries[:7]:
                        # Date Handling
                        date_tag = i.published if i.published else (i.pubDate if i.pubDate else None)
                        if date_tag:
                            try:
                                dt_obj = parser.parse(date_tag.text)
                                # Ensure timezone aware (Israel Time)
                                if dt_obj.tzinfo is None:
                                    dt_obj = pytz.utc.localize(dt_obj)
                                dt_il = dt_obj.astimezone(IL_TZ)
                                dt_iso = dt_il.isoformat()
                            except:
                                dt_iso = datetime.datetime.now(IL_TZ).isoformat()
                        else:
                            dt_iso = datetime.datetime.now(IL_TZ).isoformat()
                        
                        # Summary Handling
                        desc_tag = i.summary if i.summary else (i.description if i.description else None)
                        raw_desc = desc_tag.text if desc_tag else ""
                        soup_desc = BeautifulSoup(raw_desc, "html.parser")
                        clean_desc = soup_desc.get_text()[:600]

                        # Title Handling
                        title = i.title.text if i.title else "No Title"
                        link = i.link['href'] if i.link and i.link.has_attr('href') else (i.link.text if i.link else "#")

                        items.append({"title": title, "url": link, "date": dt_iso, "source": source['name'], "summary": clean_desc})
                    return items
                    
                elif source['type'] == 'json':
                    data = await resp.json()
                    # CISA KEV handling
                    return [{"title": f"KEV: {v['cveID']} - {v['vulnerabilityName']}", 
                             "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", 
                             "date": datetime.datetime.now(IL_TZ).isoformat(), 
                             "source": "CISA", 
                             "summary": v['shortDescription']} for v in data.get('vulnerabilities', [])[:5]]
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
        1. 'Israel'/'Iran'/'Hamas'/'Hezbollah' in text -> Category 'Israel Focus'.
        2. 'CISA' or 'CVE' -> Severity 'Critical'.
        3. 'MITRE' -> Category 'Research'.
        4. Categories choices: [Israel Focus, Malware, Phishing, Vulnerability, Research, General].
        5. Severity choices: [Critical, High, Medium, Low].
        
        Output JSON Array ONLY:
        [
          {{"id": 0, "category": "Category", "severity": "Severity", "impact": "Short impact desc", "summary": "One sentence summary."}}
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

    # Placeholder for removed classes to safely save reports
    def query_urlscan(self, ioc): return {"status": "skipped"} 

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
                    (datetime.datetime.now(IL_TZ).isoformat(), item['date'], item['source'], item['url'], item['title'], 
                     a.get('category','General'), a.get('severity','Medium'), a.get('impact','Unknown'), a.get('summary', item['summary'])))
                if c.rowcount > 0: cnt += 1
            except: pass
        conn.commit()
        conn.close()
        return cnt
    except: return 0
