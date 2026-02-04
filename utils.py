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
    limit = (datetime.datetime.now(IL_TZ) - datetime.timedelta(hours=48)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE published_at < ?", (limit,))
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

# --- CONNECTION MANAGER ---
class ConnectionManager:
    @staticmethod
    def check_groq(key):
        if not key: return False, "Missing Key"
        if key.startswith("gsk_"): return True, "Connected"
        return False, "Invalid Key Format"

# --- GROQ AI ENGINE (SUPPORTING MULTIPLE FORMATS) ---
async def query_groq_api(api_key, prompt, model="llama-3.1-8b-instant", json_mode=True):
    if not api_key: return "Error: Missing API Key"
    
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2
    }
    
    # JSON mode is ONLY for batch processing and structured data
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, json=payload, headers=headers, timeout=30) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data['choices'][0]['message']['content']
                else:
                    error_msg = await resp.text()
                    return f"Error {resp.status}: {error_msg}"
        except Exception as e:
            return f"Connection Error: {e}"

# --- AI PROCESSOR ---
class AIBatchProcessor:
    def __init__(self, key):
        self.key = key
        
    async def analyze_batch(self, items):
        if not items: return []
        if not self.key: return [{"category": "General", "severity": "Low", "summary": x['summary']} for x in items]

        chunk_size = 10
        analyzed_results = []
        
        for i in range(0, len(items), chunk_size):
            chunk = items[i:i+chunk_size]
            batch_text = "\n".join([f"ID:{idx}|Title:{x['title']}|Src:{x['source']}|Txt:{x['summary'][:300]}" for idx, x in enumerate(chunk)])
            
            prompt = f"""
            You are a CTI Analyst. Analyze these {len(chunk)} articles and return a JSON.
            Required JSON Format: {{ "items": [ {{ "id": 0, "category": "...", "severity": "...", "summary": "..." }} ] }}
            
            Data:
            {batch_text}
            """
            # Batch ingestion MUST be in JSON mode
            res = await query_groq_api(self.key, prompt, json_mode=True)
            
            chunk_map = {}
            try:
                data = json.loads(res)
                for item in data.get("items", []):
                    chunk_map[item.get('id')] = item
            except: pass
            
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
        """
        Produces a Tier 2/3 Professional Analyst Report.
        No JSON output here - just pure professional intelligence.
        """
        prompt = f"""
        Act as a Senior Cyber Threat Intelligence Analyst (Tier 3).
        Analyze the following technical data for the Indicator (IOC): {ioc}
        
        TECHNICAL CONTEXT:
        {json.dumps(data, indent=2)}
        
        TASK:
        Write a professional investigation report. Do NOT return JSON. 
        Structure your report with the following Markdown headers:
        1. 🛡️ Executive Summary (High-level verdict)
        2. 🔍 Technical Deep-Dive (Analyze VirusTotal stats, ISP, Reputation)
        3. 🎯 Targeted Threats (Is this linked to known campaigns/actors?)
        4. 🛡️ Mitigation Strategy (Immediate actions for SOC/Network teams)
        
        Tone: Professional, clinical, and authoritative.
        Language: English.
        """
        # Set json_mode=False for a natural report
        return await query_groq_api(self.key, prompt, model="llama-3.1-70b-versatile", json_mode=False)

    async def generate_hunting_queries(self, actor, news=""):
        """
        Generates detection rules without JSON conflicts.
        """
        prompt = f"""
        Act as a Detection Engineer. 
        Create hunting logic for Threat Actor: {actor['name']}
        Actor Profile: {json.dumps(actor)}
        
        TASK:
        Provide detection queries in the following formats:
        - Google SecOps (YARA-L)
        - CrowdStrike/Splunk (SPL)
        - Sentinel (KQL)
        
        Output format: Markdown with code blocks. Do NOT return JSON.
        """
        # Set json_mode=False to fix the Error 400
        return await query_groq_api(self.key, prompt, model="llama-3.1-70b-versatile", json_mode=False)

# --- COLLECTOR (REDUCED FOR BREVITY - KEEP YOUR PREVIOUS LIST) ---
class CTICollector:
    SOURCES = [
        {"name": "INCD Alerts", "url": "https://www.gov.il/he/rss/news_list", "type": "rss"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "HackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"}
    ]
    # (Keep your full fetch_item and get_all_data logic here)
    async def fetch_item(self, session, source):
        headers = {'User-Agent': 'Mozilla/5.0'}
        try:
            async with session.get(source['url'], headers=headers, timeout=15) as resp:
                if resp.status != 200: return []
                content = await resp.text()
                items = []
                now_iso = datetime.datetime.now(IL_TZ).isoformat()
                if source['type'] == 'rss':
                    feed = feedparser.parse(content)
                    for entry in feed.entries[:5]:
                        if _is_url_processed(entry.link): continue
                        summary = getattr(entry, 'summary', getattr(entry, 'description', ''))
                        clean_sum = BeautifulSoup(summary, "html.parser").get_text()[:600]
                        items.append({"title": entry.title, "url": entry.link, "date": now_iso, "source": source['name'], "summary": clean_sum})
                elif source['type'] == 'json':
                     data = json.loads(content)
                     for v in data.get('vulnerabilities', [])[:5]:
                         url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?cve={v['cveID']}"
                         if _is_url_processed(url): continue
                         items.append({"title": f"KEV: {v['cveID']}", "url": url, "date": now_iso, "source": "CISA", "summary": v.get('shortDescription')})
                return items
        except: return []

    async def get_all_data(self):
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_item(session, s) for s in self.SOURCES]
            results = await asyncio.gather(*tasks)
            return [i for sub in results for i in sub]

# --- TOOLS ---
class ThreatLookup:
    def __init__(self, vt_key=None, urlscan_key=None, abuse_ch_key=None):
        self.vt_key = vt_key
        self.urlscan_key = urlscan_key
        self.abuse_ch_key = abuse_ch_key

    def query_virustotal(self, ioc):
        if not self.vt_key: return {"error": "No Key"}
        try:
            headers = {"x-apikey": self.vt_key}
            # Try as IP first, then domain
            endpoint = "ip_addresses" if re.match(r'^\d+\.\d+\.\d+\.\d+$', ioc) else "domains"
            res = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}", headers=headers, timeout=10)
            return res.json().get('data', {}).get('attributes', {}) if res.status_code == 200 else {"error": res.status_code}
        except: return {"error": "Failed"}

    def query_urlscan(self, ioc):
        if not self.urlscan_key: return {"error": "No Key"}
        try:
            res = requests.get(f"https://urlscan.io/api/v1/search/?q={ioc}", headers={"API-Key": self.urlscan_key}, timeout=10)
            return res.json().get('results', [{}])[0] if res.status_code == 200 else {}
        except: return {}

    def query_abuseipdb(self, ip, key):
        try:
            res = requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': key, 'Accept': 'application/json'}, params={'ipAddress': ip}, timeout=10)
            return res.json().get('data', {})
        except: return {}

    def query_threatfox(self, ioc):
        try:
            res = requests.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_ioc", "search_term": ioc}, timeout=10)
            return res.json().get('data', [])
        except: return []

class APTSheetCollector:
    def fetch_threats(self): 
        return [
            {"name": "MuddyWater", "origin": "Iran", "target": "Israel", "type": "Espionage", "tools": "PowerShell, ScreenConnect", "desc": "MOIS-affiliated group targeting Israeli Gov and Infrastructure.", "mitre": "T1059"},
            {"name": "OilRig (APT34)", "origin": "Iran", "target": "Israel / Middle East", "type": "Espionage", "tools": "DNS Tunneling, SideTwist", "desc": "Sophisticated espionage targeting critical sectors.", "mitre": "T1071.004"},
            {"name": "Agonizing Serpens", "origin": "Iran", "target": "Israel", "type": "Destructive", "tools": "Wipers", "desc": "Focuses on high-impact data destruction.", "mitre": "T1485"}
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
