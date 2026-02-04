import os
import sqlite3
import asyncio
import aiohttp
import json
import datetime
import ssl
import requests
import pandas as pd
import re
import base64
from bs4 import BeautifulSoup
from dateutil import parser
import google.generativeai as genai

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
    limit = (datetime.datetime.now() - datetime.timedelta(hours=24)).isoformat()
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

def vt_url_id(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")

# --- Health Check Manager ---
class ConnectionManager:
    @staticmethod
    def check_gemini(key):
        if not key: return False, "Missing Key"
        try:
            genai.configure(api_key=key)
            genai.list_models()
            return True, "Connected"
        except Exception as e: return False, str(e)

    @staticmethod
    def check_abuseipdb(key):
        if not key: return False, "Missing Key"
        try:
            res = requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': key}, params={'ipAddress': '8.8.8.8'}, timeout=5)
            if res.status_code == 200: return True, "Connected"
            elif res.status_code == 401: return False, "Invalid API Key"
            else: return False, f"HTTP {res.status_code}"
        except Exception as e: return False, str(e)

    @staticmethod
    def check_abusech(key):
        if not key: return False, "Missing Key"
        try:
            headers = {'API-KEY': key.strip()}
            data = {'url': 'http://google.com'}
            res = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data=data, headers=headers, timeout=10)
            if res.status_code == 200: return True, "Connected"
            if res.status_code == 401: return False, "Invalid Key"
            return False, f"HTTP {res.status_code}"
        except Exception as e: return False, str(e)

    @staticmethod
    def check_virustotal(key):
        if not key: return False, "Missing Key"
        try:
            headers = {"x-apikey": key}
            res = requests.get("https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8", headers=headers, timeout=5)
            if res.status_code == 200: return True, "Connected"
            elif res.status_code == 401: return False, "Invalid API Key"
            elif res.status_code == 403: return False, "Forbidden"
            else: return False, f"HTTP {res.status_code}"
        except Exception as e: return False, str(e)

    @staticmethod
    def check_urlscan(key):
        if not key: return False, "Missing Key"
        try:
            headers = {"API-Key": key}
            res = requests.get("https://urlscan.io/api/v1/search/?q=domain:google.com", headers=headers, timeout=5)
            if res.status_code == 200: return True, "Connected"
            elif res.status_code == 401: return False, "Invalid API Key"
            else: return False, f"HTTP {res.status_code}"
        except Exception as e: return False, str(e)

# --- IOC Extractor ---
class IOCExtractor:
    def extract(self, text):
        ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        return {
            "IPs": list(set(re.findall(ipv4_pattern, text))),
            "Domains": list(set(re.findall(domain_pattern, text))),
            "Hashes": list(set(re.findall(md5_pattern, text) + re.findall(sha256_pattern, text)))
        }

# --- UNIVERSAL THREAT LOOKUP ---
class ThreatLookup:
    def __init__(self, abuse_ch_key=None, vt_key=None, urlscan_key=None, cyscan_key=None):
        self.abuse_ch_key = abuse_ch_key.strip() if abuse_ch_key else None
        self.vt_key = vt_key.strip() if vt_key else None
        self.urlscan_key = urlscan_key.strip() if urlscan_key else None
        
        self.tf_url = "https://threatfox-api.abuse.ch/api/v1/"
        self.uh_url = "https://urlhaus-api.abuse.ch/v1/url/"
        self.uh_host = "https://urlhaus-api.abuse.ch/v1/host/"
        self.uh_payload = "https://urlhaus-api.abuse.ch/v1/payload/"

    def query_threatfox(self, ioc):
        if not self.abuse_ch_key: return {"status": "skipped", "msg": "No Key"}
        ioc = ioc.strip()
        payload = {"query": "search_ioc", "search_term": ioc}
        try:
            res = requests.post(self.tf_url, json=payload, headers={'API-KEY': self.abuse_ch_key}, timeout=10)
            if res.status_code == 401: return {"status": "error", "msg": "Invalid Key"}
            data = res.json()
            if data.get("query_status") == "ok": return {"status": "found", "data": data.get("data", [])}
            elif data.get("query_status") == "no_result":
                clean_ip, port = sanitize_ioc(ioc)
                if port:
                    payload["search_term"] = clean_ip
                    res = requests.post(self.tf_url, json=payload, headers={'API-KEY': self.abuse_ch_key}, timeout=10)
                    data = res.json()
                    if data.get("query_status") == "ok": return {"status": "found", "data": data.get("data", [])}
                return {"status": "not_found"}
            return {"status": "error", "msg": data.get("query_status")}
        except Exception as e: return {"status": "error", "msg": str(e)}

    def query_urlhaus(self, ioc):
        if not self.abuse_ch_key: return {"status": "skipped", "msg": "No Key"}
        clean_ioc, _ = sanitize_ioc(ioc)
        ioc_type = get_ioc_type(clean_ioc)
        try:
            headers = {'API-KEY': self.abuse_ch_key}
            if ioc_type == "hash":
                res = requests.post(self.uh_payload, data={'md5_hash': clean_ioc} if len(clean_ioc)==32 else {'sha256_hash': clean_ioc}, headers=headers, timeout=10)
            elif ioc_type == "url":
                res = requests.post(self.uh_url, data={'url': ioc}, headers=headers, timeout=10)
            else:
                res = requests.post(self.uh_host, data={'host': clean_ioc}, headers=headers, timeout=10)
            
            if res.status_code == 200:
                data = res.json()
                if data.get("query_status") == "ok": return {"status": "found", "data": data}
                elif "urls" in data and len(data["urls"]) > 0: return {"status": "found", "data": {"tags": ["hosting_malware"], "count": len(data["urls"])}}
                return {"status": "not_found"}
            return {"status": "error", "msg": f"HTTP {res.status_code}"}
        except Exception as e: return {"status": "error", "msg": str(e)}

    def query_virustotal(self, ioc):
        if not self.vt_key: return {"status": "skipped", "msg": "No Key"}
        clean_ioc, _ = sanitize_ioc(ioc)
        ioc_type = get_ioc_type(clean_ioc)
        headers = {"x-apikey": self.vt_key}
        base_url = "https://www.virustotal.com/api/v3"
        try:
            endpoint = ""
            if ioc_type == "ip": endpoint = f"/ip_addresses/{clean_ioc}"
            elif ioc_type == "domain": endpoint = f"/domains/{clean_ioc}"
            elif ioc_type == "hash": endpoint = f"/files/{clean_ioc}"
            elif ioc_type == "url": 
                url_id = vt_url_id(ioc)
                endpoint = f"/urls/{url_id}"
            
            res = requests.get(base_url + endpoint, headers=headers, timeout=10)
            if res.status_code == 200:
                data = res.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {"status": "found", "stats": stats, "reputation": data.get("reputation", 0)}
            elif res.status_code == 404: return {"status": "not_found"}
            elif res.status_code == 401: return {"status": "error", "msg": "Invalid VT Key"}
            elif res.status_code == 429: return {"status": "error", "msg": "Rate Limit Exceeded"}
            else: return {"status": "error", "msg": f"HTTP {res.status_code}"}
        except Exception as e: return {"status": "error", "msg": str(e)}

    def query_urlscan(self, ioc):
        if not self.urlscan_key: return {"status": "skipped", "msg": "No Key"}
        clean_ioc, _ = sanitize_ioc(ioc)
        try:
            headers = {"API-Key": self.urlscan_key}
            query = f'"{clean_ioc}"'
            res = requests.get(f"https://urlscan.io/api/v1/search/?q={query}", headers=headers, timeout=10)
            if res.status_code == 200:
                data = res.json()
                results = data.get("results", [])
                if results:
                    latest = results[0]
                    return {
                        "status": "found",
                        "page": latest.get("page", {}),
                        "task": latest.get("task", {}),
                        "verdict": latest.get("verdict", {}),
                        "screenshot": latest.get("screenshot")
                    }
                return {"status": "not_found"}
            elif res.status_code == 401: return {"status": "error", "msg": "Invalid URLScan Key"}
            else: return {"status": "error", "msg": f"HTTP {res.status_code}"}
        except Exception as e: return {"status": "error", "msg": str(e)}

    def query_cyscan(self, ioc):
        return {"link": f"https://cyscan.io/search/{ioc}"}

# --- Collectors ---
class MitreCollector:
    def get_latest_updates(self):
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            resp = requests.get("https://attack.mitre.org/resources/updates/", headers=headers, timeout=5)
            soup = BeautifulSoup(resp.text, 'html.parser')
            update = soup.find('h2')
            if update: return {"title": update.text.strip(), "url": "https://attack.mitre.org" + (update.find('a')['href'] if update.find('a') else "")}
            return None
        except: return None

class APTSheetCollector:
    def __init__(self):
        self.base = "https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/export?format=csv&gid="
        self.gids = {"Israel": "1864660085", "Russia": "1636225066", "China": "0", "Iran": "0"}
    def fetch_threats(self, region="Israel"):
        try:
            url = self.base + self.gids.get(region, "0")
            df = pd.read_csv(url).head(50)
            return df
        except: return pd.DataFrame()

class AbuseIPDBChecker:
    def __init__(self, key): self.key = key
    def check_ip(self, ip):
        if not self.key: return {"error": "Missing Key"}
        clean_ip, _ = sanitize_ioc(ip)
        try:
            res = requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': self.key}, params={'ipAddress': clean_ip, 'maxAgeInDays': 90})
            if res.status_code == 200: return {"success": True, "data": res.json()['data']}
            elif res.status_code == 422: return {"error": "Skipped: Not a valid IP"}
            elif res.status_code == 401: return {"error": "Invalid API Key"}
            else: return {"error": f"API Error: {res.text}"}
        except: return {"error": "Connection Failed"}

class CTICollector:
    SOURCES = [
        {"name": "CheckPoint", "url": "https://research.checkpoint.com/feed/", "type": "rss"},
        {"name": "ClearSky (IL)", "url": "https://www.clearskysec.com/feed/", "type": "rss"},
        {"name": "Israel Defense", "url": "https://www.israeldefense.co.il/en/rss.xml", "type": "rss"},
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"}
    ]
    async def fetch_item(self, session, source):
        headers = {'User-Agent': 'Mozilla/5.0'}
        try:
            async with session.get(source['url'], headers=headers, timeout=10) as resp:
                if resp.status != 200: return []
                now = datetime.datetime.now(datetime.timezone.utc)
                if source['type'] == 'rss':
                    soup = BeautifulSoup(await resp.text(), 'xml')
                    items = []
                    for i in soup.find_all('item')[:10]:
                        d = i.pubDate.text if i.pubDate else str(now)
                        try:
                            dt = parser.parse(d)
                            if dt.tzinfo is None: dt = dt.replace(tzinfo=datetime.timezone.utc)
                            if dt < now - datetime.timedelta(hours=24): continue
                            final_d = dt.isoformat()
                        except: final_d = now.isoformat()
                        items.append({"title": i.title.text, "url": i.link.text, "date": final_d, "source": source['name'], "summary": i.description.text if i.description else ""})
                    return items
                elif source['type'] == 'json':
                    data = await resp.json()
                    return [{"title": f"KEV: {v['cveID']}", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "date": datetime.datetime.now().isoformat(), "source": source['name'], "summary": v['vulnerabilityName']} for v in data.get('vulnerabilities', [])[:3]]
        except: return []
    
    async def get_all_data(self):
        ssl_ctx = ssl.create_default_context(); ssl_ctx.check_hostname=False; ssl_ctx.verify_mode=ssl.CERT_NONE
        conn = aiohttp.TCPConnector(ssl=ssl_ctx)
        async with aiohttp.ClientSession(connector=conn) as session:
            tasks = [self.fetch_item(session, src) for src in self.SOURCES]
            results = await asyncio.gather(*tasks)
            return [i for sub in results for i in sub]

# --- AI Processors ---
class AIBatchProcessor:
    def __init__(self, key):
        self.key = key
        if key:
            genai.configure(api_key=key)

    async def analyze_batch(self, items):
        if not items or not self.key: return []
        batch_text = "\n".join([f"ID:{i}|Src:{item['source']}|Title:{item['title']}" for i,item in enumerate(items)])
        prompt = f"""
        SOC Analysis.
        Categories: [Phishing, Vulnerability, Research, Israel Focus, Malware, DDoS, General].
        Severity: [Critical, High, Medium, Low].
        Rules: 'Israel Focus' if context matches. KEV=Critical. Marketing=IGNORE.
        Items: {batch_text}
        Output JSON: [{{"id":0, "category":"...", "severity":"...", "impact":"...", "summary":"..."}}]
        """
        for m in ["gemini-2.0-flash", "gemini-2.5-flash", "gemini-1.5-flash"]:
            try:
                model = genai.GenerativeModel(m)
                res = await model.generate_content_async(prompt)
                return json.loads(res.text.replace('```json','').replace('```','').strip())
            except: continue
        return []

    # This was missing in your previous code
    async def analyze_single_ioc(self, ioc, data):
        if not self.key: return "No API Key configured."
        
        # Prepare context data as string
        context_str = json.dumps(data, indent=2, default=str)
        
        prompt = f"""
        Act as a Level 3 SOC Analyst. 
        I have investigated an Indicator of Compromise (IOC): {ioc}.
        
        Here is the collected intelligence data from various sources (VirusTotal, AbuseIPDB, ThreatFox, etc.):
        {context_str}
        
        Please provide a concise but professional investigation report in Markdown format.
        Include:
        1. **Verdict**: (Malicious / Suspicious / Benign / Inconclusive) with a confidence score.
        2. **Summary of Findings**: What makes this IOC good or bad based on the data provided?
        3. **Key Evidence**: Bullet points of specific flags (e.g., high abuse score, specific malware tag).
        4. **Recommended Action**: What should the SOC team do? (Block, Monitor, Ignore).
        
        Keep it operational and direct.
        """
        
        for m in ["gemini-2.0-flash", "gemini-2.5-flash", "gemini-1.5-flash"]:
            try:
                model = genai.GenerativeModel(m)
                res = await model.generate_content_async(prompt)
                return res.text
            except Exception as e:
                continue
        return "Error: Could not generate analysis. Please check API Key or Quota."

def save_reports(raw, analyzed):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        amap = {r['id']:r for r in analyzed if r.get('category')!='IGNORE'}
        cnt = 0
        for i,item in enumerate(raw):
            if i in amap:
                a = amap[i]
                c.execute("INSERT OR IGNORE INTO intel_reports (timestamp,published_at,source,url,title,category,severity,impact,summary) VALUES (?,?,?,?,?,?,?,?,?)",
                    (datetime.datetime.now().isoformat(), item['date'], item['source'], item['url'], item['title'], a['category'], a['severity'], a['impact'], a['summary']))
                if c.rowcount > 0: cnt += 1
        conn.commit(); conn.close()
        return cnt
    except: return 0
