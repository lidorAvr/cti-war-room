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
import random
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

# --- AI CORE (BRUTE FORCE DISPATCHER) ---
async def query_gemini_auto(api_key, prompt):
    """
    Tries multiple model versions until one works.
    Handles 404 (Model Not Found) and 429 (Quota) automatically.
    """
    if not api_key: return "Error: Missing API Key"
    
    # List of models to try in order of preference
    # Google frequently changes these aliases, so we try them all.
    candidates = [
        "gemini-1.5-flash",
        "gemini-1.5-flash-latest",
        "gemini-1.5-pro",
        "gemini-1.0-pro",
        "gemini-pro"
    ]
    
    headers = {'Content-Type': 'application/json'}
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    
    async with aiohttp.ClientSession() as session:
        for model in candidates:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
            
            # Retry logic for 429 (Quota) specific to this model
            for attempt in range(3):
                try:
                    async with session.post(url, json=payload, headers=headers, timeout=30) as resp:
                        if resp.status == 200:
                            # Success!
                            data = await resp.json()
                            return data['candidates'][0]['content']['parts'][0]['text']
                        
                        elif resp.status == 404:
                            # Model not found, break retry loop and try next model
                            # print(f"DEBUG: {model} not found (404), trying next...")
                            break 
                            
                        elif resp.status == 429:
                            # Rate limit, wait and retry same model
                            wait = (2 ** attempt) + random.uniform(0, 1)
                            await asyncio.sleep(wait)
                            continue
                            
                        else:
                            # Other error (500 etc), try next model
                            break
                except:
                    break # Network error, try next model

    return "❌ Error: AI Unresponsive. All models failed or API Key is invalid."

# --- CONNECTION MGR ---
class ConnectionManager:
    @staticmethod
    def check_gemini(key):
        if not key: return False, "Missing Key"
        # Try a simple ping to find ANY working model
        models = ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-pro"]
        for m in models:
            try:
                res = requests.post(f"https://generativelanguage.googleapis.com/v1beta/models/{m}:generateContent?key={key}", 
                                  json={"contents":[{"parts":[{"text":"Ping"}]}]}, timeout=5)
                if res.status_code == 200: return True, f"Connected ({m})"
            except: pass
        return False, "Connection Failed (Check Key/Quota)"

# --- COLLECTOR (HYBRID: RSS + SCRAPING) ---
class CTICollector:
    SOURCES = [
        # ISRAEL FOCUS
        {"name": "INCD Alerts", "url": "https://www.gov.il/he/departments/news/news-list", "type": "html_gov_il"}, 
        {"name": "Calcalist Cyber", "url": "https://www.calcalist.co.il/calcalistech/category/4799", "type": "html_calcalist"},
        {"name": "JPost Cyber", "url": "https://www.jpost.com/rss/rssfeedscontainer.aspx?type=115", "type": "rss"},
        
        # GLOBAL & RESEARCH
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"},
        {"name": "CheckPoint Research", "url": "https://research.checkpoint.com/feed/", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        {"name": "Google Threat Intel", "url": "https://feeds.feedburner.com/GoogleOnlineSecurityBlog", "type": "rss"},
        {"name": "ESET WeLiveSecurity", "url": "https://www.welivesecurity.com/feed/", "type": "rss"}
    ]
    
    async def fetch_item(self, session, source):
        headers = {'User-Agent': 'Mozilla/5.0'}
        try:
            async with session.get(source['url'], headers=headers, timeout=15) as resp:
                if resp.status != 200: return []
                content = await resp.text()
                items = []
                now_iso = datetime.datetime.now(IL_TZ).isoformat()

                if source['type'] == 'rss':
                    soup = BeautifulSoup(content, 'xml')
                    entries = soup.find_all('entry') or soup.find_all('item')
                    for i in entries[:5]:
                        date_tag = i.published if i.published else (i.pubDate if i.pubDate else None)
                        dt_iso = self.parse_date(date_tag.text if date_tag else None)
                        
                        raw_desc = (i.summary.text if i.summary else (i.description.text if i.description else ""))
                        clean_desc = BeautifulSoup(raw_desc, "html.parser").get_text()[:600]
                        link = i.link['href'] if i.link and i.link.has_attr('href') else (i.link.text if i.link else "#")
                        title = i.title.text if i.title else "No Title"
                        items.append({"title": title, "url": link, "date": dt_iso, "source": source['name'], "summary": clean_desc})
                
                elif source['type'] == 'json':
                    data = json.loads(content)
                    return [{"title": f"KEV: {v['cveID']} - {v['vulnerabilityName']}", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", 
                             "date": now_iso, "source": "CISA", "summary": v['shortDescription']} for v in data.get('vulnerabilities', [])[:5]]

                elif source['type'] == 'html_gov_il':
                    soup = BeautifulSoup(content, 'html.parser')
                    for article in soup.find_all('div', class_='row item')[:5]:
                        link_tag = article.find('a')
                        if link_tag:
                            title = link_tag.get_text().strip()
                            url = "https://www.gov.il" + link_tag['href'] if link_tag['href'].startswith('/') else link_tag['href']
                            items.append({"title": title, "url": url, "date": now_iso, "source": source['name'], "summary": "Government Publication"})

                elif source['type'] == 'html_calcalist':
                    soup = BeautifulSoup(content, 'html.parser')
                    for art in soup.find_all('div', class_='MainItem')[:5]:
                        h1 = art.find('h1')
                        if h1:
                            link = h1.find('a')
                            if link:
                                items.append({"title": link.get_text().strip(), "url": link['href'], "date": now_iso, "source": source['name'], "summary": "Calcalist Tech Report"})
                return items
        except: return []

    def parse_date(self, date_str):
        if not date_str: return datetime.datetime.now(IL_TZ).isoformat()
        try:
            dt_obj = parser.parse(date_str)
            if dt_obj.tzinfo is None: dt_obj = pytz.utc.localize(dt_obj)
            return dt_obj.astimezone(IL_TZ).isoformat()
        except: return datetime.datetime.now(IL_TZ).isoformat()

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
            
        items = items[:20] # Limit to avoid timeouts
        batch_text = "\n".join([f"ID:{i}|Src:{x['source']}|Title:{x['title']}" for i,x in enumerate(items)])
        
        prompt = f"""
        Act as a Cyber Intelligence Analyst.
        Rules:
        1. 'Israel'/'Iran'/'Hamas' -> Category 'Israel Focus'.
        2. 'CISA'/'CVE' -> Severity 'Critical'.
        3. Marketing/Sales -> Category 'General', Severity 'Low'.
        
        Output JSON Array ONLY:
        [
          {{"id": 0, "category": "Israel Focus/Malware/Phishing/Vulnerability/General", "severity": "Critical/High/Medium/Low", "impact": "Short impact desc", "summary": "One sentence summary."}}
        ]
        
        Items:
        {batch_text}
        """
        res = await query_gemini_auto(self.key, prompt)
        if res and "Error" not in res:
            try:
                clean = res.replace('```json','').replace('```','').strip()
                if '[' in clean: clean = clean[clean.find('['):clean.rfind(']')+1]
                return json.loads(clean)
            except: pass
        return [{"id": i, "category": "General", "severity": "Medium", "impact": "AI Error", "summary": x['summary'][:200]} for i,x in enumerate(items)]

    async def analyze_single_ioc(self, ioc, data):
        prompt = f"Investigate IOC: {ioc}. Data: {json.dumps(data, default=str)}. Return Markdown report: Verdict, Summary, Evidence, Action."
        return await query_gemini_auto(self.key, prompt)

    async def generate_hunting_queries(self, actor_profile, recent_news=""):
        prompt = f"""
        Act as Detection Engineer. Threat Actor: {actor_profile['name']}.
        Tools: {actor_profile['tools']}
        
        Output Markdown:
        ### 🧠 Strategy (Simple English)
        Briefly explain the hunting strategy.

        ### 🛡️ Detection Queries
        
        **1. Google SecOps (YARA-L)**
        ```yaral
        rule {actor_profile['name'].replace(' ','_')}_Hunt {{
           meta:
              author = "SOC War Room"
           events:
              $e.metadata.event_type = "PROCESS_LAUNCH"
              // Add logic for {actor_profile['tools']}
           condition:
              $e
        }}
        ```

        **2. Cortex XDR (XQL)**
        ```sql
        dataset = xdr_data 
        | filter event_type = PROCESS 
        | filter action_process_image_name ~= "powershell.exe"
        // Add logic
        ```
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
        if not self.keys['urlscan']: return {"status": "skipped", "msg": "No API Key"}
        try:
            res = requests.get(f"https://urlscan.io/api/v1/search/?q={ioc}", headers={"API-Key": self.keys['urlscan']}, timeout=10)
            if res.status_code == 200:
                data = res.json()
                if data.get("results"):
                    result = data["results"][0]
                    return {"status": "found", "screenshot": result.get("screenshot"), "verdict": result.get("verdict"), "page": result.get("page")}
                return {"status": "not_found", "msg": "No scan found"}
            elif res.status_code == 401: return {"status": "error", "msg": "Invalid Key"}
            return {"status": "error", "msg": f"HTTP {res.status_code}"}
        except Exception as e: return {"status": "error", "msg": str(e)}

class APTSheetCollector:
    def fetch_threats(self, region=None): 
        return [
            {"name": "MuddyWater", "origin": "🇮🇷 Iran", "type": "Espionage", "target": "Israel, Saudi Arabia", "tools": "PowerShell, ScreenConnect", "desc": "MOIS-affiliated group targeting government and telco.", "mitre": "T1059.001"},
            {"name": "OilRig (APT34)", "origin": "🇮🇷 Iran", "type": "Espionage", "target": "Middle East Finance", "tools": "DNS Tunneling, Karkoff", "desc": "Uses supply chain attacks and sophisticated backdoors.", "mitre": "T1071.004"},
            {"name": "Agonizing Serpens", "origin": "🇮🇷 Iran", "type": "Wiper / Destructive", "target": "Israel Education & Tech", "tools": "Multi-Layer Wipers", "desc": "Focuses on data destruction and psychological warfare.", "mitre": "T1485"},
            {"name": "Lazarus Group", "origin": "🇰🇵 North Korea", "type": "Financial Theft", "target": "Global Defense & Crypto", "tools": "Manuscrypt", "desc": "State-sponsored actor funding the regime via crypto theft.", "mitre": "T1003"},
            {"name": "APT28 (Fancy Bear)", "origin": "🇷🇺 Russia", "type": "Sabotage", "target": "NATO, Ukraine", "tools": "X-Agent", "desc": "GRU unit involved in high-profile disinformation and hacks.", "mitre": "T1110"},
            {"name": "Imperial Kitten", "origin": "🇮🇷 Iran", "type": "Espionage", "target": "Maritime, Logistics", "tools": "Social Engineering", "desc": "IRGC-affiliated, targets transportation and defense.", "mitre": "T1566"}
        ]

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
