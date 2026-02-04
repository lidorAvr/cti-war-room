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
from bs4 import BeautifulSoup
from dateutil import parser as date_parser

DB_NAME = "cti_dashboard.db"
IL_TZ = pytz.timezone('Asia/Jerusalem')

# --- IOC VALIDATION ---
def identify_ioc_type(ioc):
    """
    Validates input and returns type: 'ip', 'domain', 'hash', or None.
    """
    ioc = ioc.strip()
    # Check IP
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass
    
    # Check Hash (MD5, SHA1, SHA256)
    if re.match(r'^[a-fA-F0-9]{32}$', ioc) or re.match(r'^[a-fA-F0-9]{40}$', ioc) or re.match(r'^[a-fA-F0-9]{64}$', ioc):
        return "hash"
    
    # Check Domain (Simple regex)
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
    
    # CLEANUP STRATEGY:
    # 1. Delete INCD reports older than 96 hours (4 days) - BUT logic in app handles "Last 4" keeping.
    # 2. Delete regular reports older than 48 hours.
    limit_regular = (datetime.datetime.now(IL_TZ) - datetime.timedelta(hours=48)).isoformat()
    limit_incd = (datetime.datetime.now(IL_TZ) - datetime.timedelta(hours=96)).isoformat()
    
    # We delete carefully to respect the rules (App logic will filter viewing, DB cleanup prevents bloat)
    c.execute("DELETE FROM intel_reports WHERE source != 'INCD' AND published_at < ?", (limit_regular,))
    c.execute("DELETE FROM intel_reports WHERE source = 'INCD' AND published_at < ?", (limit_incd,))
    
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
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.3} # Low temp for consistency
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
        
    async def analyze_batch(self, items):
        if not items: return []
        chunk_size = 10
        results = []
        
        system_instruction = """
        You are a CTI Analyst. Analyze cyber news.
        1. SEVERITY: 'Critical', 'High', 'Medium', 'Low'.
        2. CATEGORY (Choose ONE strictly): 'Phishing', 'Malware', 'Vulnerabilities', 'News', 'Research', 'Other'. 
           Use 'Other' only if absolutely nothing else fits.
        3. SUMMARY: Concise Hebrew summary (max 20 words).
        Return JSON format: {"items": [{"id": 0, "category": "...", "severity": "...", "summary": "..."}]}
        """
        
        for i in range(0, len(items), chunk_size):
            chunk = items[i:i+chunk_size]
            batch_text = "\n".join([f"ID:{idx}|Title:{x['title']}|Src:{x['source']}|Txt:{x['summary'][:200]}" for idx, x in enumerate(chunk)])
            prompt = f"{system_instruction}\nData to Analyze:\n{batch_text}"
            
            res = await query_groq_api(self.key, prompt, json_mode=True)
            chunk_map = {}
            try:
                data = json.loads(res)
                for item in data.get("items", []): chunk_map[item.get('id')] = item
            except: pass
            
            for j in range(len(chunk)):
                ai = chunk_map.get(j, {})
                # Fallback defaults
                results.append({
                    "category": ai.get('category', 'News'), 
                    "severity": ai.get('severity', 'Medium'), 
                    "summary": ai.get('summary', chunk[j]['summary'][:100])
                })
        return results

    async def analyze_single_ioc(self, ioc, ioc_type, data):
        # Tier 3 Mentor Persona
        prompt = f"""
        Act as a Tier 3 CTI Mentor explaining findings to a Tier 1 Analyst.
        Target: {ioc} ({ioc_type}).
        Raw Data from Scanners: {json.dumps(data)}
        
        Output Structure (Markdown):
        1. **Executive Verdict**: Is it Malicious? (Yes/No/Suspicious). Why? (Clear and decisive).
        2. **Technical Analysis**: Break down the findings. Explain *what* the indicators mean (e.g., "High entropy indicates packing").
        3. **Enrichment**: Add general knowledge about this threat type or specific malware family if detected.
        4. **Next Steps**: Detailed instructions for the Tier 1 analyst (e.g., "Block in Firewall", "Search logs for X", "Isolate host").
        
        Tone: Educational, professional, authoritative but helpful. Hebrew or English (User preference: Hebrew).
        """
        return await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)

    async def generate_hunting_queries(self, actor):
        prompt = f"""
        Generate Hunting Queries for Actor: {actor['name']}.
        Based on Mitre Techniques: {actor.get('mitre', 'N/A')} and Tools: {actor.get('tools', 'N/A')}.
        
        Required Output Formats:
        1. **Google Chronicle (YARA-L)**: Valid syntax.
        2. **Cortex XDR (XQL)**: Valid syntax.
        3. **Splunk (SPL)**: Optional but good to have.
        
        Explain logic for each query briefly.
        """
        return await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)

class ThreatLookup:
    def __init__(self, vt_key=None, urlscan_key=None, abuse_key=None):
        self.vt_key, self.urlscan_key, self.abuse_key = vt_key, urlscan_key, abuse_key

    def query_virustotal(self, ioc, ioc_type):
        if not self.vt_key: return None
        try:
            endpoint = "ip_addresses" if ioc_type == "ip" else "domains" if ioc_type == "domain" else "files"
            res = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}", headers={"x-apikey": self.vt_key}, timeout=10)
            return res.json().get('data', {}).get('attributes', {}) if res.status_code == 200 else None
        except: return None

    def query_urlscan(self, ioc):
        if not self.urlscan_key: return None
        try:
            res = requests.get(f"https://urlscan.io/api/v1/search/?q={ioc}", headers={"API-Key": self.urlscan_key}, timeout=10)
            return res.json().get('results', [{}])[0] if res.status_code == 200 else None
        except: return None

    def query_abuseipdb(self, ip):
        if not self.abuse_key: return None
        try:
            res = requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': self.abuse_key, 'Accept': 'application/json'}, params={'ipAddress': ip}, timeout=10)
            return res.json().get('data', {})
        except: return None

# --- STRATEGIC INTEL ---
class APTSheetCollector:
    def fetch_threats(self): 
        # Simulated "Live" logic - in production, this could parse the G-Sheet
        return [
            {"name": "MuddyWater", "origin": "Iran", "target": "Israel", "type": "Espionage", "tools": "PowerShell, ScreenConnect", "desc": "Subordinate to MOIS. Targets Israeli Gov/Telecom.", "mitre": "T1059, T1105"},
            {"name": "OilRig (APT34)", "origin": "Iran", "target": "Israel / Middle East", "type": "Espionage", "tools": "DNS Tunneling, SideTwist", "desc": "High sophistication. Targets Critical Infra.", "mitre": "T1071.004, T1048"},
            {"name": "Agonizing Serpens", "origin": "Iran", "target": "Israel", "type": "Destructive", "tools": "Wipers (BiBiWiper)", "desc": "Destructive attacks masquerading as ransomware.", "mitre": "T1485, T1486"},
            {"name": "Imperial Kitten", "origin": "Iran", "target": "Israel", "type": "Espionage/Cyber-Enabled Influence", "tools": "IMAPLoader, Standard Python Backdoors", "desc": "IRGC affiliated. Focus on transportation and logistics.", "mitre": "T1566, T1071"}
        ]

# --- DATA COLLECTION ---
class CTICollector:
    SOURCES = [
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "HackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        # INCD Sources
        {"name": "INCD", "url": "https://www.gov.il/he/collectors/publications?officeId=4bcc13f5-fed6-4b8c-b8ee-7bf4a6bc81c8", "type": "gov_il"},
        {"name": "INCD", "url": "https://t.me/s/Israel_Cyber", "type": "telegram"} 
    ]

    async def fetch_item(self, session, source):
        items = []
        try:
            async with session.get(source['url'], headers={'User-Agent': 'Mozilla/5.0'}, timeout=15) as resp:
                if resp.status != 200: return []
                content = await resp.text()
                now = datetime.datetime.now(IL_TZ)

                # --- RSS PARSER ---
                if source['type'] == 'rss':
                    feed = feedparser.parse(content)
                    for entry in feed.entries[:10]:
                        if _is_url_processed(entry.link): continue
                        
                        # Extract Publish Date
                        pub_date = now
                        if hasattr(entry, 'published_parsed') and entry.published_parsed:
                            pub_date = datetime.datetime(*entry.published_parsed[:6]).replace(tzinfo=pytz.utc).astimezone(IL_TZ)
                        
                        # General 48h filter
                        if (now - pub_date).total_seconds() > 172800: continue

                        sum_text = BeautifulSoup(getattr(entry, 'summary', ''), "html.parser").get_text()[:600]
                        items.append({"title": entry.title, "url": entry.link, "date": pub_date.isoformat(), "source": source['name'], "summary": sum_text})

                # --- JSON PARSER (CISA) ---
                elif source['type'] == 'json':
                     data = json.loads(content)
                     for v in data.get('vulnerabilities', [])[:10]:
                         url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?cve={v['cveID']}"
                         if _is_url_processed(url): continue
                         # CISA date format: YYYY-MM-DD
                         try: 
                             pub_date = date_parser.parse(v['dateAdded']).replace(tzinfo=IL_TZ)
                         except: 
                             pub_date = now
                        
                         if (now - pub_date).total_seconds() > 172800: continue
                         items.append({"title": f"KEV: {v['cveID']}", "url": url, "date": pub_date.isoformat(), "source": "CISA", "summary": v.get('shortDescription')})

                # --- TELEGRAM PARSER (INCD) ---
                elif source['type'] == 'telegram':
                    soup = BeautifulSoup(content, 'html.parser')
                    msgs = soup.find_all('div', class_='tgme_widget_message_wrap')
                    for msg in msgs[-10:]: # Look at last 10
                        try:
                            text_div = msg.find('div', class_='tgme_widget_message_text')
                            if not text_div: continue
                            text = text_div.get_text()
                            
                            # Find date
                            time_span = msg.find('time', class_='time')
                            if time_span and 'datetime' in time_span.attrs:
                                pub_date = date_parser.parse(time_span['datetime']).astimezone(IL_TZ)
                            else:
                                pub_date = now

                            # INCD Rule: Keep for 4 days (345600 seconds)
                            if (now - pub_date).total_seconds() > 345600: continue
                            
                            # Construct Link
                            post_link = msg.find('a', class_='tgme_widget_message_date')['href']
                            
                            if _is_url_processed(post_link): continue
                            
                            items.append({
                                "title": "INCD Alert (Telegram)",
                                "url": post_link,
                                "date": pub_date.isoformat(),
                                "source": "INCD",
                                "summary": text[:600]
                            })
                        except: continue

                # --- GOV.IL PARSER (INCD Website) ---
                elif source['type'] == 'gov_il':
                    # Note: scraping gov.il can be tricky due to dynamic loading. 
                    # Simulating a simple meta fetch if structure permits, or fallback to generic link extraction.
                    # Ideally, would use Selenium/Playwright but staying with requests/BS4 as per requirements.
                    soup = BeautifulSoup(content, 'html.parser')
                    # This is generic best-effort for Gov.il structure
                    links = soup.find_all('a', href=True)
                    for link in links:
                        href = link['href']
                        if "/news/" in href or "/publications/" in href:
                            full_url = "https://www.gov.il" + href if href.startswith("/") else href
                            if _is_url_processed(full_url): continue
                            items.append({
                                "title": link.get_text(strip=True),
                                "url": full_url,
                                "date": now.isoformat(), # Difficult to parse date from list page without JS
                                "source": "INCD",
                                "summary": "Official Publication"
                            })

        except Exception as e: 
            print(f"Error fetching {source['name']}: {e}")
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
            try:
                c.execute("INSERT OR IGNORE INTO intel_reports (timestamp,published_at,source,url,title,category,severity,summary) VALUES (?,?,?,?,?,?,?,?)",
                    (datetime.datetime.now(IL_TZ).isoformat(), item['date'], item['source'], item['url'], item['title'], a['category'], a['severity'], a['summary']))
                if c.rowcount > 0: cnt += 1
            except: pass
    conn.commit()
    conn.close()
    return cnt
