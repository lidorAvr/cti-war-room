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

# --- AI WRAPPER (REST API) ---
class AIHandler:
    def __init__(self, api_key):
        self.api_key = api_key
        # שימוש במודל היציב והזול ביותר מבחינת מכסה
        self.url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"

    def _query(self, prompt):
        if not self.api_key: return None
        
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        headers = {'Content-Type': 'application/json'}
        
        # מנגנון ניסיון חוזר (Retry) חכם
        for i in range(3):
            try:
                response = requests.post(self.url, json=payload, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    try:
                        return response.json()['candidates'][0]['content']['parts'][0]['text']
                    except:
                        return "Error parsing AI response"
                
                elif response.status_code == 429:
                    # אם יש עומס - מחכים זמן אקראי
                    time.sleep(2 + random.random())
                    continue
                
                else:
                    return f"Error {response.status_code}: {response.text}"
            except Exception as e:
                return f"Connection Error: {str(e)}"
        
        return "AI Busy (Rate Limit)"

    def analyze_batch(self, items):
        if not items: return []
        
        # ניתוח קבוצתי - חוסך 95% מהבקשות!
        # לוקחים רק את ה-15 הראשונים כדי לא לחרוג
        batch = items[:15]
        text_data = "\n".join([f"ID:{i} | Title: {x['title']}" for i,x in enumerate(batch)])
        
        prompt = f"""
        Act as a SOC Analyst. Classify these cyber news headlines.
        
        Rules:
        1. Categories: Israel Focus, Malware, Vulnerability, General.
        2. Severity: Critical, High, Medium, Low.
        3. If title contains 'Israel', 'Iran', 'Hamas' -> 'Israel Focus'.
        4. If title contains 'CISA', 'CVE' -> 'Critical'.
        
        Input Data:
        {text_data}
        
        Output strictly a JSON list:
        [
            {{"id": 0, "category": "...", "severity": "...", "summary": "Short summary"}}
        ]
        """
        
        res = self._query(prompt)
        try:
            clean = res.replace('```json','').replace('```','').strip()
            return json.loads(clean)
        except:
            return [{"id": i, "category": "General", "severity": "Medium", "summary": "Analysis Pending"} for i in range(len(batch))]

    def generate_hunting(self, actor):
        prompt = f"""
        Write detections for actor: {actor['name']} (Tools: {actor['tools']}).
        Output Markdown:
        1. **Google SecOps (YARA-L)** Rule.
        2. **Cortex XDR (XQL)** Query.
        3. **Splunk (SPL)** Query.
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
        {"name": "CheckPoint Research", "url": "https://research.checkpoint.com/feed/", "type": "rss"}
    ]

    def fetch_all(self):
        results = []
        headers = {'User-Agent': 'Mozilla/5.0'}
        now_iso = datetime.datetime.now(IL_TZ).isoformat()
        
        for source in self.SOURCES:
            try:
                resp = requests.get(source['url'], headers=headers, timeout=10)
                if resp.status_code != 200: continue
                content = resp.text
                
                if source['type'] == 'rss':
                    soup = BeautifulSoup(content, 'xml')
                    for item in soup.find_all('item')[:3]: # רק 3 אחרונים מכל מקור לחיסכון
                        results.append({
                            "title": item.title.text,
                            "url": item.link.text,
                            "date": now_iso,
                            "source": source['name']
                        })

                elif source['type'] == 'json':
                    data = resp.json()
                    for v in data.get('vulnerabilities', [])[:3]:
                        results.append({
                            "title": f"KEV: {v['cveID']}",
                            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                            "date": now_iso,
                            "source": "CISA"
                        })
                
                elif source['type'] == 'html_gov':
                    soup = BeautifulSoup(content, 'html.parser')
                    for div in soup.find_all('div', class_='row item')[:3]:
                        a = div.find('a')
                        if a: results.append({"title": a.get_text().strip(), "url": "https://www.gov.il"+a['href'], "date": now_iso, "source": "INCD"})

                elif source['type'] == 'html_calcalist':
                    soup = BeautifulSoup(content, 'html.parser')
                    for div in soup.find_all('div', class_='MainItem')[:3]:
                        h1 = div.find('h1')
                        if h1 and h1.find('a'):
                            results.append({"title": h1.find('a').get_text().strip(), "url": h1.find('a')['href'], "date": now_iso, "source": "Calcalist"})

            except: continue
        return results

# --- SAVE ---
def save_reports(raw, analyzed):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    cnt = 0
    # Map raw to analyzed
    amap = {x['id']: x for x in analyzed if isinstance(x, dict) and 'id' in x}
    
    for i, item in enumerate(raw):
        # Default values if AI failed or skipped
        cat = "General"
        sev = "Medium"
        summ = "Click link to read"
        
        if i in amap:
            cat = amap[i].get('category', cat)
            sev = amap[i].get('severity', sev)
            summ = amap[i].get('summary', summ)
            
        try:
            c.execute("INSERT OR IGNORE INTO intel_reports (timestamp,published_at,source,url,title,category,severity,impact,summary) VALUES (?,?,?,?,?,?,?,?,?)",
                (datetime.datetime.now(IL_TZ).isoformat(), item['date'], item['source'], item['url'], item['title'], 
                 cat, sev, "Info", summ))
            if c.rowcount > 0: cnt += 1
        except: pass
    conn.commit()
    conn.close()
    return cnt

# --- APT DATA ---
class APTData:
    @staticmethod
    def get_actors():
        return [
            {"name": "MuddyWater", "origin": "Iran", "target": "Israel", "tools": "PowerShell"},
            {"name": "OilRig", "origin": "Iran", "target": "Middle East", "tools": "DNS Tunneling"},
            {"name": "Lazarus", "origin": "North Korea", "target": "Finance", "tools": "Manuscrypt"}
        ]

# --- THREAT LOOKUP ---
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
                return {"status": "found", "data": "Found in VT"}
            return {"status": "not_found"}
        except: return {"status": "error"}

    def check_urlscan(self, ioc):
        if not self.us: return {"status": "skipped"}
        try:
            r = requests.get(f"https://urlscan.io/api/v1/search/?q={ioc}", headers={'API-Key': self.us})
            if r.status_code == 200 and r.json().get('results'):
                return {"status": "found", "data": r.json()['results'][0]}
            return {"status": "not_found"}
        except: return {"status": "error"}
