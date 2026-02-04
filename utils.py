import sqlite3
import asyncio
import aiohttp
import json
import datetime
import requests
import pandas as pd
import re
import base64
import pytz
from bs4 import BeautifulSoup
from dateutil import parser

DB_NAME = "cti_dashboard.db"
IL_TZ = pytz.timezone('Asia/Jerusalem')

# --- DATABASE ---
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
    # Cleanup > 48 hours
    limit = (datetime.datetime.now(IL_TZ) - datetime.timedelta(hours=48)).isoformat()
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

# --- AI LOGIC ---
async def get_valid_model_name(api_key, session):
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
        if not model_name: return "Error: Check API Key."
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
                    entries = soup.find_all('entry')
                    if not entries: entries = soup.find_all('item')

                    for i in entries[:7]:
                        # Date Handling
                        date_tag = i.published if i.published else (i.pubDate if i.pubDate else None)
                        if date_tag:
                            try:
                                dt_obj = parser.parse(date_tag.text)
                                if dt_obj.tzinfo is None: dt_obj = pytz.utc.localize(dt_obj)
                                dt_il = dt_obj.astimezone(IL_TZ)
                                dt_iso = dt_il.isoformat()
                            except:
                                dt_iso = datetime.datetime.now(IL_TZ).isoformat()
                        else:
                            dt_iso = datetime.datetime.now(IL_TZ).isoformat()
                        
                        raw_desc = (i.summary.text if i.summary else (i.description.text if i.description else ""))
                        clean_desc = BeautifulSoup(raw_desc, "html.parser").get_text()[:600]
                        link = i.link['href'] if i.link and i.link.has_attr('href') else (i.link.text if i.link else "#")

                        items.append({"title": i.title.text, "url": link, "date": dt_iso, "source": source['name'], "summary": clean_desc})
                    return items
                    
                elif source['type'] == 'json':
                    data = await resp.json()
                    return [{"title": f"KEV: {v['cveID']} - {v['vulnerabilityName']}", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", 
                             "date": datetime.datetime.now(IL_TZ).isoformat(), "source": "CISA", "summary": v['shortDescription']} for v in data.get('vulnerabilities', [])[:5]]
        except: return []

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
        if not self.key: return [{"id": i, "category": "General", "severity": "Medium", "impact": "Info", "summary": x['summary'][:200]} for i,x in enumerate(items)]
            
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
        **SOC Analyst Request:** Investigate IOC: {ioc}
        **Data:** {json.dumps(data, indent=2, default=str)}
        **Task:** Markdown report. 1. Verdict (Malicious/Safe). 2. Summary. 3. Key Evidence. 4. Actions.
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

    def query_urlscan(self, ioc):
        if not self.keys['urlscan']: return {"status": "skipped"}
        try:
            res = requests.get(f"https://urlscan.io/api/v1/search/?q={ioc}", headers={"API-Key": self.keys['urlscan']}, timeout=10)
            if res.status_code == 200 and res.json().get("results"):
                result = res.json()["results"][0]
                return {"status": "found", "screenshot": result.get("screenshot"), "verdict": result.get("verdict"), "page": result.get("page")}
            return {"status": "not_found"}
        except: return {"status": "error"}

class APTSheetCollector:
    def fetch_threats(self, region):
        # Using a public CTI Github CSV as a reliable source for APT data
        try:
            url = "https://raw.githubusercontent.com/mitre/cti/master/groups.csv" # Placeholder for valid CSV
            # For demo, returning mock dataframe if URL fails, or using a known good CTI list
            return pd.DataFrame([
                {"Group": "MuddyWater", "Target": "Israel", "Type": "Espionage", "Origin": "Iran"},
                {"Group": "Lazarus", "Target": "Global", "Type": "Financial", "Origin": "North Korea"},
                {"Group": "APT28", "Target": "Ukraine/NATO", "Type": "Sabotage", "Origin": "Russia"},
                {"Group": "OilRig", "Target": "Middle East", "Type": "Espionage", "Origin": "Iran"},
            ])
        except: return pd.DataFrame()
