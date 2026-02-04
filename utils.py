import sqlite3
import datetime
import pandas as pd
import re
import pytz
import requests
import json
import time
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

# --- AI WRAPPER (DYNAMIC MODEL DISCOVERY) ---
class AIHandler:
    def __init__(self, api_key):
        self.api_key = api_key
        self.base_url = "https://generativelanguage.googleapis.com/v1beta"
        self.working_model = None

    def _discover_model(self):
        """Asks Google which models are available for this Key to avoid 404"""
        if self.working_model: return self.working_model
        
        try:
            url = f"{self.base_url}/models?key={self.api_key}"
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                # Prefer Flash, but take whatever works
                for m in data.get('models', []):
                    if 'generateContent' in m.get('supportedGenerationMethods', []):
                        # print(f"DEBUG: Found model {m['name']}")
                        self.working_model = m['name'].replace('models/', '')
                        if 'flash' in self.working_model: break # Stop if we found flash
                return self.working_model
        except: pass
        return "gemini-1.5-flash" # Fallback

    def _query(self, prompt):
        if not self.api_key: return "Error: Missing Key"
        
        model = self._discover_model()
        url = f"{self.base_url}/models/{model}:generateContent?key={self.api_key}"
        headers = {'Content-Type': 'application/json'}
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        
        for i in range(3): # Retry logic
            try:
                response = requests.post(url, json=payload, headers=headers, timeout=40)
                if response.status_code == 200:
                    return response.json()['candidates'][0]['content']['parts'][0]['text']
                elif response.status_code == 429:
                    time.sleep(2) # Wait for rate limit
                    continue
                else:
                    return f"AI Error {response.status_code}: {response.text}"
            except Exception as e:
                return f"Conn Error: {str(e)}"
        return "AI Busy"

    def analyze_batch(self, items):
        if not items: return []
        # Analyze in batches of 15 to save requests
        batch = items[:15]
        text_data = "\n".join([f"ID:{i} | Title: {x['title']}" for i,x in enumerate(batch)])
        
        prompt = f"""
        Act as a SOC Analyst.
        Rules:
        1. Categories: Israel Focus, Malware, Vulnerability, General.
        2. Severity: Critical, High, Medium, Low.
        3. 'Israel'/'Iran'/'Hamas' in title -> 'Israel Focus'.
        4. 'CISA'/'CVE' -> 'Critical'.
        
        Input:
        {text_data}
        
        Output JSON:
        [
            {{"id": 0, "category": "...", "severity": "...", "summary": "Short summary"}}
        ]
        """
        res = self._query(prompt)
        try:
            clean = res.replace('```json','').replace('```','').strip()
            return json.loads(clean)
        except:
            return [{"id": i, "category": "General", "severity": "Medium", "summary": "Pending Analysis"} for i in range(len(batch))]

    def generate_hunting(self, actor):
        prompt = f"""
        Create hunting queries for Threat Actor: {actor['name']} ({actor['tools']}).
        Output Markdown:
        1. **Google Chronicle (YARA-L)**
        2. **Cortex XDR (XQL)**
        3. **Splunk (SPL)**
        4. **Analyst Note (Tier 1)**
        """
        return self._query(prompt)

# --- HYBRID COLLECTOR ---
class CTICollector:
    SOURCES = [
        {"name": "INCD Alerts", "url": "https://www.gov.il/he/departments/news/news-list", "type": "html_gov"},
        {"name": "Calcalist Cyber", "url": "https://www.calcalist.co.il/calcalistech/category/4799", "type": "html_calcalist"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"},
        {"name": "CheckPoint", "url": "https://research.checkpoint.com/feed/", "type": "rss"}
    ]

    def fetch_all(self):
        results = []
        headers = {'User-Agent': 'Mozilla/5.0'}
        now = datetime.datetime.now(IL_TZ).isoformat()
        
        for source in self.SOURCES:
            try:
                r = requests.get(source['url'], headers=headers, timeout=10)
                if r.status_code != 200: continue
                
                if source['type'] == 'rss':
                    soup = BeautifulSoup(r.text, 'xml')
                    for item in soup.find_all('item')[:4]:
                        results.append({
                            "title": item.title.text,
                            "url": item.link.text,
                            "date": now,
                            "source": source['name']
                        })
                elif source['type'] == 'json':
                    data = r.json()
                    for v in data.get('vulnerabilities', [])[:4]:
                        results.append({
                            "title": f"KEV: {v['cveID']} - {v['vulnerabilityName']}",
                            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                            "date": now,
                            "source": "CISA"
                        })
                elif source['type'] == 'html_gov':
                    soup = BeautifulSoup(r.text, 'html.parser')
                    for div in soup.find_all('div', class_='row item')[:4]:
                        a = div.find('a')
                        if a: results.append({"title": a.get_text().strip(), "url": "https://www.gov.il"+a['href'], "date": now, "source": "INCD"})
                elif source['type'] == 'html_calcalist':
                    soup = BeautifulSoup(r.text, 'html.parser')
                    for div in soup.find_all('div', class_='MainItem')[:4]:
                        h1 = div.find('h1')
                        if h1 and h1.find('a'):
                            results.append({"title": h1.find('a').get_text().strip(), "url": h1.find('a')['href'], "date": now, "source": "Calcalist"})
            except: continue
        return results

# --- SAVE ---
def save_reports(raw, analyzed):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    cnt = 0
    amap = {x['id']:x for x in analyzed if isinstance(x, dict) and 'id' in x}
    
    for i, item in enumerate(raw):
        a = amap.get(i, {})
        try:
            c.execute("INSERT OR IGNORE INTO intel_reports (timestamp,published_at,source,url,title,category,severity,impact,summary) VALUES (?,?,?,?,?,?,?,?,?)",
                (datetime.datetime.now(IL_TZ).isoformat(), item['date'], item['source'], item['url'], item['title'], 
                 a.get('category','General'), a.get('severity','Medium'), 'Info', a.get('summary', item['title'])))
            if c.rowcount > 0: cnt += 1
        except: pass
    conn.commit()
    conn.close()
    return cnt

# --- LOOKUP TOOLS ---
class ThreatLookup:
    def __init__(self, vt, us, ab):
        self.vt = vt
        self.us = us
        self.ab = ab
    
    def check_vt(self, ioc):
        if not self.vt: return {"status": "skipped"}
        try:
            u = f"https://www.virustotal.com/api/v3/search?query={ioc}"
            r = requests.get(u, headers={'x-apikey': self.vt})
            if r.status_code == 200 and r.json().get('data'):
                return {"status": "found", "data": "Found in VT Database"}
            return {"status": "not_found"}
        except: return {"error"}

    def check_urlscan(self, ioc):
        if not self.us: return {"status": "skipped"}
        try:
            r = requests.get(f"https://urlscan.io/api/v1/search/?q={ioc}", headers={'API-Key': self.us})
            if r.status_code == 200 and r.json().get('results'):
                return {"status": "found", "data": r.json()['results'][0]}
            return {"status": "not_found"}
        except: return {"error"}

class APTData:
    @staticmethod
    def get_actors():
        return [
            {"name": "MuddyWater", "origin": "🇮🇷 Iran", "target": "Israel", "tools": "PowerShell, ScreenConnect"},
            {"name": "OilRig (APT34)", "origin": "🇮🇷 Iran", "target": "Finance", "tools": "DNS Tunneling"},
            {"name": "Agonizing Serpens", "origin": "🇮🇷 Iran", "target": "Education", "tools": "Wipers"},
            {"name": "Lazarus", "origin": "🇰🇵 NK", "target": "Crypto", "tools": "Manuscrypt"},
            {"name": "APT28", "origin": "🇷🇺 Russia", "target": "Ukraine", "tools": "Mimikatz"}
        ]
