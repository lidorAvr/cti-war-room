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
    ioc = ioc.strip()
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
    
    # Cleanup: Keep INCD for 96h, others for 48h
    limit_regular = (datetime.datetime.now(IL_TZ) - datetime.timedelta(hours=48)).isoformat()
    limit_incd = (datetime.datetime.now(IL_TZ) - datetime.timedelta(hours=96)).isoformat()
    
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
        
    async def analyze_batch(self, items):
        if not items: return []
        chunk_size = 10
        results = []
        
        system_instruction = """
        You are a CTI Analyst. Analyze cyber news.
        1. SEVERITY: 'Critical', 'High', 'Medium', 'Low'.
        2. CATEGORY (Choose ONE strictly): 'Phishing', 'Malware', 'Vulnerabilities', 'News', 'Research', 'Other'.
        3. SUMMARY: Concise English summary (max 25 words). Focus on the threat.
        Return JSON format: {"items": [{"id": 0, "category": "...", "severity": "...", "summary": "..."}]}
        """
        
        for i in range(0, len(items), chunk_size):
            chunk = items[i:i+chunk_size]
            batch_text = "\n".join([f"ID:{idx}|Title:{x['title']}|Src:{x['source']}|Txt:{x['summary'][:250]}" for idx, x in enumerate(chunk)])
            prompt = f"{system_instruction}\nData to Analyze:\n{batch_text}"
            
            res = await query_groq_api(self.key, prompt, json_mode=True)
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
                    "summary": ai.get('summary', chunk[j]['summary'][:200])
                })
        return results

    async def analyze_single_ioc(self, ioc, ioc_type, data):
        prompt = f"""
        Act as a Tier 3 CTI Analyst.
        Target: {ioc} ({ioc_type}).
        Raw Data: {json.dumps(data)}
        
        Output Structure (Markdown):
        1. **Executive Verdict**: Malicious/Suspicious/Clean. Why?
        2. **Technical Analysis**: Key findings from the data.
        3. **Enrichment**: What usually does this (e.g., Cobalt Strike, specific APT)?
        4. **Recommendations**: Block, Hunt, or Ignore.
        """
        return await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)

    async def generate_hunting_queries(self, actor):
        prompt = f"""
        Generate Hunting Queries for Actor: {actor['name']}.
        Context: {actor.get('mitre', 'N/A')} | {actor.get('tools', 'N/A')}.
        
        Provide:
        1. **Google Chronicle (YARA-L)**
        2. **Cortex XDR (XQL)**
        
        Explain the logic briefly in English.
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
        return [
            {"name": "MuddyWater", "origin": "Iran", "target": "Israel", "type": "Espionage", "tools": "PowerShell, ScreenConnect", "desc": "MOIS-affiliated group targeting Israeli Gov and Infrastructure.", "mitre": "T1059, T1105"},
            {"name": "OilRig (APT34)", "origin": "Iran", "target": "Israel / Middle East", "type": "Espionage", "tools": "DNS Tunneling, SideTwist", "desc": "Sophisticated espionage targeting critical sectors.", "mitre": "T1071.004, T1048"},
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
        # INCD: Using specific scrapers
        {"name": "INCD", "url": "https://www.gov.il/he/collectors/publications?officeId=4bcc13f5-fed6-4b8c-b8ee-7bf4a6bc81c8", "type": "gov_il"},
        {"name": "INCD", "url": "https://t.me/s/Israel_Cyber", "type": "telegram"} 
    ]

    async def fetch_item(self, session, source):
        items = []
        try:
            async with session.get(source['url'], headers={'User-Agent': 'Mozilla/5.0'}, timeout=20) as resp:
                if resp.status != 200: return []
                content = await resp.text()
                now = datetime.datetime.now(IL_TZ)

                if source['type'] == 'rss':
                    feed = feedparser.parse(content)
                    for entry in feed.entries[:10]:
                        if _is_url_processed(entry.link): continue
                        pub_date = now
                        if hasattr(entry, 'published_parsed') and entry.published_parsed:
                            pub_date = datetime.datetime(*entry.published_parsed[:6]).replace(tzinfo=pytz.utc).astimezone(IL_TZ)
                        if (now - pub_date).total_seconds() > 172800: continue
                        sum_text = BeautifulSoup(getattr(entry, 'summary', ''), "html.parser").get_text()[:600]
                        items.append({"title": entry.title, "url": entry.link, "date": pub_date.isoformat(), "source": source['name'], "summary": sum_text})

                elif source['type'] == 'json':
                     data = json.loads(content)
                     for v in data.get('vulnerabilities', [])[:10]:
                         url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?cve={v['cveID']}"
                         if _is_url_processed(url): continue
                         try: pub_date = date_parser.parse(v['dateAdded']).replace(tzinfo=IL_TZ)
                         except: pub_date = now
                         if (now - pub_date).total_seconds() > 172800: continue
                         items.append({"title": f"KEV: {v['cveID']}", "url": url, "date": pub_date.isoformat(), "source": "CISA", "summary": v.get('shortDescription')})

                elif source['type'] == 'telegram':
                    # Improved Telegram Parsing for Israel_Cyber
                    soup = BeautifulSoup(content, 'html.parser')
                    msgs = soup.find_all('div', class_='tgme_widget_message_wrap')
                    for msg in msgs[-10:]:
                        try:
                            text_div = msg.find('div', class_='tgme_widget_message_text')
                            if not text_div: continue
                            text = text_div.get_text(separator=' ')
                            
                            # Date parsing
                            pub_date = now
                            time_span = msg.find('time', class_='time')
                            if time_span and 'datetime' in time_span.attrs:
                                try:
                                    pub_date = date_parser.parse(time_span['datetime']).astimezone(IL_TZ)
                                except: pass
                            
                            # 4 Days rule for INCD
                            if (now - pub_date).total_seconds() > 345600: continue
                            
                            # Link extraction
                            post_link = ""
                            date_link = msg.find('a', class_='tgme_widget_message_date')
                            if date_link: post_link = date_link['href']
                            else: post_link = f"https://t.me/s/Israel_Cyber?q={text[:10]}"
                            
                            if _is_url_processed(post_link): continue
                            
                            items.append({
                                "title": "INCD Alert (Telegram)", 
                                "url": post_link, 
                                "date": pub_date.isoformat(), 
                                "source": "INCD", 
                                "summary": text[:800]
                            })
                        except Exception as e: 
                            # Continue to next message on error
                            pass

                elif source['type'] == 'gov_il':
                    # Generic fallback for gov.il
                    soup = BeautifulSoup(content, 'html.parser')
                    # Look for news/publications links
                    links = soup.select('a[href*="/news/"], a[href*="/publications/"]')
                    for link in links[:5]:
                        href = link['href']
                        full_url = "https://www.gov.il" + href if href.startswith("/") else href
                        if _is_url_processed(full_url): continue
                        
                        items.append({
                            "title": link.get_text(strip=True), 
                            "url": full_url, 
                            "date": now.isoformat(), 
                            "source": "INCD", 
                            "summary": "Official Publication from Gov.il"
                        })

        except Exception as e: pass
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
