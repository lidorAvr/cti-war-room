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
import feedparser
from bs4 import BeautifulSoup
from dateutil import parser

DB_NAME = "cti_dashboard.db"
IL_TZ = pytz.timezone('Asia/Jerusalem')

# --- DATABASE MANAGEMENT ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Create main report table
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
    c.execute("CREATE INDEX IF NOT EXISTS idx_url ON intel_reports(url)")
    
    # Auto-cleanup: Keep only last 48 hours of data
    limit = (datetime.datetime.now(IL_TZ) - datetime.timedelta(hours=48)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE published_at < ?", (limit,))
    conn.commit()
    conn.close()

def _is_url_processed(url):
    """Check if URL exists in DB to prevent re-processing"""
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT id FROM intel_reports WHERE url = ?", (url,))
        result = c.fetchone()
        conn.close()
        return result is not None
    except: return False

# --- CONNECTION MANAGER ---
class ConnectionManager:
    """
    Helper class to test API connections.
    """
    @staticmethod
    def check_groq(key):
        if not key: return False, "Missing Key"
        if key.startswith("gsk_"): return True, "Connected"
        return False, "Invalid Key Format"

# --- GROQ AI ENGINE ---
async def query_groq_api(api_key, prompt, model="llama-3.1-8b-instant"):
    if not api_key: return "Error: Missing API Key"
    
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.1,
        "response_format": {"type": "json_object"} # Force JSON structure
    }
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, json=payload, headers=headers, timeout=20) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data['choices'][0]['message']['content']
                elif resp.status == 429:
                    return "Rate Limit Hit"
                else:
                    return f"Error {resp.status}"
        except Exception as e:
            return f"Connection Error: {e}"

# --- AI PROCESSOR ---
class AIBatchProcessor:
    def __init__(self, key):
        self.key = key
        
    async def analyze_batch(self, items):
        if not items: return []
        if not self.key: 
            # Fallback if no key: just return items as is
            return [{"category": "General", "severity": "Low", "summary": x['summary']} for x in items]

        # Process in chunks of 10 to utilize Groq speed
        chunk_size = 10
        analyzed_results = []
        
        for i in range(0, len(items), chunk_size):
            chunk = items[i:i+chunk_size]
            
            # Create a compressed prompt
            batch_text = "\n".join([f"ID:{idx}|Title:{x['title']}|Src:{x['source']}|Txt:{x['summary'][:300]}" for idx, x in enumerate(chunk)])
            
            prompt = f"""
            You are a Cyber Threat Intelligence (CTI) Analyst. Analyze these {len(chunk)} articles.
            
            INPUT DATA:
            {batch_text}
            
            INSTRUCTIONS:
            1. Return a JSON Object with a key "items" containing a list.
            2. Each item must have: "id" (int), "category", "severity", "summary" (concise).
            3. Logic:
               - "Israel Focus": Mention of Israel, Iran, Hamas, Hezbollah, Gov.il, Check Point, Wiz.
               - "Critical": CVE, Active Exploitation, Zero-Day, Ransomware.
               - "Malware": Trojan, Backdoor, Loader, Stealer.
            
            JSON OUTPUT EXAMPLE:
            {{ "items": [ {{ "id": 0, "category": "Israel Focus", "severity": "High", "summary": "Short summary here." }} ] }}
            """
            
            res = await query_groq_api(self.key, prompt)
            
            # Parse the JSON response
            chunk_map = {}
            if res and "{" in res:
                try:
                    data = json.loads(res)
                    if "items" in data:
                        for item in data["items"]:
                            chunk_map[item.get('id')] = item
                except: pass
            
            # Map back to original order
            for j in range(len(chunk)):
                ai_data = chunk_map.get(j, {})
                analyzed_results.append({
                    "category": ai_data.get('category', 'General'),
                    "severity": ai_data.get('severity', 'Medium'),
                    "summary": ai_data.get('summary', chunk[j]['summary']),
                    "impact": "AI Analyzed"
                })
                
        return analyzed_results

    async def analyze_single_ioc(self, ioc, data):
        prompt = f"Analyze this IOC: {ioc}. Threat Data: {json.dumps(data)}. Return JSON with fields: verdict, summary, next_steps."
        return await query_groq_api(self.key, prompt)

    async def generate_hunting_queries(self, actor, news=""):
        prompt = f"Create hunting queries (YARA-L, Splunk) for threat actor: {actor['name']}. Return formatted Markdown."
        return await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile")

# --- COLLECTOR ---
class CTICollector:
    SOURCES = [
        # ISRAEL
        {"name": "Gov.il Publications", "url": "https://www.gov.il/he/rss/publications", "type": "rss"},
        {"name": "INCD Alerts", "url": "https://www.gov.il/he/rss/news_list", "type": "rss"},
        {"name": "JPost Cyber", "url": "https://www.jpost.com/rss/rssfeedscontainer.aspx?type=115", "type": "rss"},
        
        # GLOBAL
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "The Record", "url": "https://therecord.media/feed", "type": "rss"},
        
        # RESEARCH
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
    ]
    
    async def fetch_item(self, session, source):
        headers = {'User-Agent': 'Mozilla/5.0'}
        try:
            async with session.get(source['url'], headers=headers, timeout=15) as resp:
                if resp.status != 200: return []
                content = await resp.text()
                items = []
                now_iso = datetime.datetime.now(IL_TZ).isoformat()
                
                # RSS Handler
                if source['type'] == 'rss':
                    feed = feedparser.parse(content)
                    for entry in feed.entries[:5]: # Top 5 items
                        if _is_url_processed(entry.link): continue
                        
                        summary = getattr(entry, 'summary', getattr(entry, 'description', ''))
                        clean_sum = BeautifulSoup(summary, "html.parser").get_text()[:600]
                        
                        items.append({
                            "title": entry.title, 
                            "url": entry.link, 
                            "date": now_iso, 
                            "source": source['name'], 
                            "summary": clean_sum
                        })
                
                # JSON Handler (CISA)
                elif source['type'] == 'json':
                     data = json.loads(content)
                     for v in data.get('vulnerabilities', [])[:5]:
                         url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?cve={v['cveID']}"
                         if _is_url_processed(url): continue
                         items.append({
                             "title": f"KEV: {v['cveID']}", 
                             "url": url, 
                             "date": now_iso, 
                             "source": "CISA", 
                             "summary": v.get('shortDescription')
                         })
                return items
        except: return []

    async def get_all_data(self):
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_item(session, s) for s in self.SOURCES]
            results = await asyncio.gather(*tasks)
            return [i for sub in results for i in sub]

# --- TOOLS & HELPERS ---
class ThreatLookup:
    def __init__(self, **kwargs): pass
    # Placeholder methods for API lookups
    def query_virustotal(self, ioc): return {"status": "mock", "msg": "API Key Required"}
    def query_urlscan(self, ioc): return {"status": "mock", "msg": "API Key Required"}
    def query_abuseipdb(self, ip, k): return {}
    def query_threatfox(self, ioc): return {}
    def query_urlhaus(self, ioc): return {}

class APTSheetCollector:
    def fetch_threats(self): 
        return [
            {"name": "MuddyWater", "origin": "Iran", "target": "Israel", "type": "Espionage", "tools": "PowerShell", "desc": "MOIS-affiliated group.", "mitre": "T1059"},
            {"name": "OilRig", "origin": "Iran", "target": "Finance", "type": "Espionage", "tools": "DNS Tunneling", "desc": "APT34 Supply Chain.", "mitre": "T1071"},
            {"name": "Lazarus Group", "origin": "North Korea", "target": "Defense", "type": "Financial", "tools": "Manuscrypt", "desc": "Crypto theft & Espionage.", "mitre": "T1003"}
        ]

def save_reports(raw, analyzed):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    cnt = 0
    for i, item in enumerate(raw):
        if i < len(analyzed):
            a = analyzed[i]
            try:
                c.execute("INSERT OR IGNORE INTO intel_reports (timestamp,published_at,source,url,title,category,severity,impact,summary) VALUES (?,?,?,?,?,?,?,?,?)",
                    (datetime.datetime.now(IL_TZ).isoformat(), item['date'], item['source'], item['url'], item['title'], 
                     a.get('category','General'), a.get('severity','Medium'), a.get('impact','Unknown'), a.get('summary', item['summary'])))
                if c.rowcount > 0: cnt += 1
            except: pass
    conn.commit()
    conn.close()
    return cnt
