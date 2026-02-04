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
        if not key: return False, "חסר מפתח"
        if key.startswith("gsk_"): return True, "מחובר"
        return False, "פורמט לא תקין"

async def query_groq_api(api_key, prompt, model="llama-3.1-8b-instant", json_mode=True):
    if not api_key: return "שגיאה: חסר מפתח API"
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
        You are an Israeli CTI Analyst. Analyze cyber news.
        1. SEVERITY: 'Critical', 'High', 'Medium', 'Low'.
        2. CATEGORY (Choose ONE strictly): 'Phishing', 'Malware', 'Vulnerabilities', 'News', 'Research', 'Other'.
        3. SUMMARY: Concise **Hebrew** summary (max 20 words). Write specifically for Israeli security teams.
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
                results.append({
                    "category": ai.get('category', 'News'), 
                    "severity": ai.get('severity', 'Medium'), 
                    "summary": ai.get('summary', chunk[j]['summary'][:100])
                })
        return results

    async def analyze_single_ioc(self, ioc, ioc_type, data):
        prompt = f"""
        Act as a Tier 3 CTI Mentor explaining findings to a Tier 1 Analyst (Hebrew Speaker).
        Target: {ioc} ({ioc_type}).
        Raw Data: {json.dumps(data)}
        
        **CRITICAL LANGUAGE INSTRUCTIONS:**
        1. Write primarily in **HEBREW**.
        2. **STRICTLY AVOID** English transliteration for technical terms. Use proper Hebrew terms:
           - Malicious -> **זדוני** (Not "מליציוס")
           - Suspicious -> **חשוד**
           - Clean/Harmless -> **נקי**
           - Vulnerability -> **חולשה**
           - Attack -> **תקיפה**
        3. Keep specific tool names or error codes in English (e.g., "HTTP 404", "Cobalt Strike").

        Output Structure (Markdown):
        1. **פסיקת מנהלים (Verdict)**: Is it זדוני? Why? (Be decisive).
        2. **ניתוח טכני (Analysis)**: Explain findings.
        3. **העשרה (Enrichment)**: Context about this threat type.
        4. **צעדים להמשך (Next Steps)**: Actionable items.
        """
        return await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)

    async def generate_hunting_queries(self, actor):
        prompt = f"""
        Generate Hunting Queries for Actor: {actor['name']}.
        Context: {actor.get('mitre', 'N/A')} | {actor.get('tools', 'N/A')}.
        
        **INSTRUCTIONS:**
        1. The Code Blocks must be valid syntax (English).
        2. The **Explanations** describing the logic MUST be in **HEBREW**.
        
        Provide:
        1. **Google Chronicle (YARA-L)**
           - Code block
           - Hebrew Explanation of what it hunts for.
        2. **Cortex XDR (XQL)**
           - Code block
           - Hebrew Explanation.
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
            {"name": "MuddyWater", "origin": "איראן", "target": "ישראל", "type": "ריגול", "tools": "PowerShell, ScreenConnect", "desc": "קבוצה הכפופה ל-MOIS. מתמקדת במגזר הממשלתי והתקשורת בישראל.", "mitre": "T1059, T1105"},
            {"name": "OilRig (APT34)", "origin": "איראן", "target": "ישראל / מזה\"ת", "type": "ריגול", "tools": "DNS Tunneling, SideTwist", "desc": "קבוצה מתוחכמת המתמקדת בתשתיות קריטיות.", "mitre": "T1071.004, T1048"},
            {"name": "Agonizing Serpens", "origin": "איראן", "target": "ישראל", "type": "הרס (Destructive)", "tools": "Wipers (BiBiWiper)", "desc": "תקיפות הרסניות במסווה של כופרה (Ransomware).", "mitre": "T1485, T1486"},
            {"name": "Imperial Kitten", "origin": "איראן", "target": "ישראל", "type": "ריגול / השפעה", "tools": "IMAPLoader, Standard Python Backdoors", "desc": "מזוהה עם משמרות המהפכה (IRGC). מתמקדת בלוגיסטיקה ותחבורה.", "mitre": "T1566, T1071"}
        ]

# --- DATA COLLECTION ---
class CTICollector:
    SOURCES = [
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "HackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
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
                    soup = BeautifulSoup(content, 'html.parser')
                    msgs = soup.find_all('div', class_='tgme_widget_message_wrap')
                    for msg in msgs[-10:]:
                        try:
                            text_div = msg.find('div', class_='tgme_widget_message_text')
                            if not text_div: continue
                            text = text_div.get_text()
                            time_span = msg.find('time', class_='time')
                            if time_span and 'datetime' in time_span.attrs:
                                pub_date = date_parser.parse(time_span['datetime']).astimezone(IL_TZ)
                            else: pub_date = now
                            if (now - pub_date).total_seconds() > 345600: continue
                            post_link = msg.find('a', class_='tgme_widget_message_date')['href']
                            if _is_url_processed(post_link): continue
                            items.append({"title": "התראת מערך הסייבר (Telegram)", "url": post_link, "date": pub_date.isoformat(), "source": "INCD", "summary": text[:600]})
                        except: continue

                elif source['type'] == 'gov_il':
                    soup = BeautifulSoup(content, 'html.parser')
                    links = soup.find_all('a', href=True)
                    for link in links:
                        href = link['href']
                        if "/news/" in href or "/publications/" in href:
                            full_url = "https://www.gov.il" + href if href.startswith("/") else href
                            if _is_url_processed(full_url): continue
                            items.append({"title": link.get_text(strip=True), "url": full_url, "date": now.isoformat(), "source": "INCD", "summary": "פרסום רשמי באתר הממשלתי"})

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
