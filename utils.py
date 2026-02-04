import sqlite3
import datetime
import pandas as pd
import re
import pytz
import google.generativeai as genai
import requests
from bs4 import BeautifulSoup
from dateutil import parser
import time
import json

DB_NAME = "cti_dashboard.db"
IL_TZ = pytz.timezone('Asia/Jerusalem')

# --- DATABASE SETUP ---
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
    # ניקוי אוטומטי של ידיעות ישנות (מעל 48 שעות)
    limit = (datetime.datetime.now(IL_TZ) - datetime.timedelta(hours=48)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE published_at < ?", (limit,))
    conn.commit()
    conn.close()

# --- GOOGLE AI WRAPPER (OFFICIAL LIB) ---
class AIHandler:
    def __init__(self, api_key):
        self.api_key = api_key
        if api_key:
            genai.configure(api_key=api_key)
    
    def analyze_batch(self, items):
        if not items or not self.api_key: return []
        
        # צמצום כמות כדי למנוע עומס
        batch = items[:25]
        text_data = "\n".join([f"ID:{i}|Title:{x['title']}|Source:{x['source']}" for i,x in enumerate(batch)])
        
        prompt = f"""
        Act as a SOC Analyst. Analyze these headlines.
        Rules:
        1. 'Israel'/'Iran'/'Hamas' -> Category 'Israel Focus'.
        2. 'CISA'/'CVE' -> Severity 'Critical'.
        3. Marketing/Sales -> Category 'General', Severity 'Low'.
        
        Output JSON list: [{{ "id": 0, "category": "...", "severity": "...", "impact": "...", "summary": "..." }}]
        
        Data:
        {text_data}
        """
        
        try:
            model = genai.GenerativeModel('gemini-1.5-flash')
            response = model.generate_content(prompt)
            clean = response.text.replace('```json','').replace('```','').strip()
            return json.loads(clean)
        except:
            # Fallback במקרה של שגיאה
            return [{"id": i, "category": "General", "severity": "Medium", "impact": "Pending", "summary": "Analysis Pending"} for i in range(len(batch))]

    def generate_hunting(self, actor):
        if not self.api_key: return "⚠️ Missing API Key"
        
        prompt = f"""
        Act as a Detection Engineer. Create hunting rules for Threat Actor: {actor['name']}.
        Tools/Malware: {actor['tools']}
        
        Output Markdown format:
        ### 🧠 Analyst Explanation
        Simple explanation of what we are looking for.

        ### 🛡️ Detection Rules
        **1. Google SecOps (Chronicle YARA-L)**
        ```yaral
        // Write a specific rule for {actor['name']} tools
        ```
        
        **2. Cortex XDR (XQL)**
        ```sql
        // Write a specific XQL query
        ```
        """
        try:
            model = genai.GenerativeModel('gemini-1.5-flash')
            return model.generate_content(prompt).text
        except Exception as e:
            return f"AI Error: {str(e)}"

# --- HYBRID COLLECTOR ---
class CTICollector:
    SOURCES = [
        {"name": "INCD Alerts", "url": "https://www.gov.il/he/departments/news/news-list", "type": "html_gov"},
        {"name": "Calcalist Cyber", "url": "https://www.calcalist.co.il/calcalistech/category/4799", "type": "html_calcalist"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"},
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
                    items = soup.find_all('item')[:5]
                    for item in items:
                        results.append({
                            "title": item.title.text,
                            "url": item.link.text,
                            "date": now_iso,
                            "source": source['name'],
                            "summary": BeautifulSoup(item.description.text, "html.parser").get_text()[:300]
                        })

                elif source['type'] == 'json':
                    data = resp.json()
                    for v in data.get('vulnerabilities', [])[:5]:
                        results.append({
                            "title": f"KEV: {v['cveID']} - {v['vulnerabilityName']}",
                            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                            "date": now_iso,
                            "source": "CISA",
                            "summary": v['shortDescription']
                        })
                
                # HTML Scraping for Israeli Sites
                elif source['type'] == 'html_gov':
                    soup = BeautifulSoup(content, 'html.parser')
                    for div in soup.find_all('div', class_='row item')[:5]:
                        a = div.find('a')
                        if a:
                            results.append({
                                "title": a.get_text().strip(),
                                "url": "https://www.gov.il" + a['href'],
                                "date": now_iso,
                                "source": "INCD",
                                "summary": "Official Gov Alert"
                            })
                            
                elif source['type'] == 'html_calcalist':
                    soup = BeautifulSoup(content, 'html.parser')
                    for div in soup.find_all('div', class_='MainItem')[:5]:
                        h1 = div.find('h1')
                        if h1 and h1.find('a'):
                            results.append({
                                "title": h1.find('a').get_text().strip(),
                                "url": h1.find('a')['href'],
                                "date": now_iso,
                                "source": "Calcalist",
                                "summary": "Tech News Report"
                            })

            except: continue
                
        return results

# --- THREAT TOOLS ---
class ThreatLookup:
    def __init__(self, vt_key, urlscan_key, abuse_key):
        self.vt = vt_key
        self.us = urlscan_key
        self.ab = abuse_key

    def check_vt(self, ioc):
        if not self.vt: return {"status": "skipped"}
        try:
            # Simple check
            u = f"https://www.virustotal.com/api/v3/search?query={ioc}"
            r = requests.get(u, headers={'x-apikey': self.vt}, timeout=5)
            if r.status_code == 200:
                data = r.json()
                if data.get('data'):
                    # Get stats from the first result
                    obj_id = data['data'][0]['id']
                    obj_type = data['data'][0]['type']
                    u2 = f"https://www.virustotal.com/api/v3/{obj_type}s/{obj_id}"
                    r2 = requests.get(u2, headers={'x-apikey': self.vt})
                    return {"status": "found", "data": r2.json()['data']['attributes']['last_analysis_stats']}
            return {"status": "not_found"}
        except: return {"status": "error"}

    def check_urlscan(self, ioc):
        if not self.us: return {"status": "skipped"}
        try:
            r = requests.get(f"https://urlscan.io/api/v1/search/?q={ioc}", headers={'API-Key': self.us}, timeout=5)
            if r.status_code == 200:
                d = r.json()
                if d.get('results'):
                    res = d['results'][0]
                    return {
                        "status": "found",
                        "verdict": res.get('verdict', {}).get('overall', 'Unknown'),
                        "screenshot": res.get('screenshot')
                    }
            return {"status": "not_found"}
        except: return {"status": "error"}

class APTData:
    @staticmethod
    def get_actors():
        return [
            {"name": "MuddyWater", "origin": "🇮🇷 Iran", "type": "Espionage", "target": "Israel", "tools": "PowerShell, ScreenConnect"},
            {"name": "OilRig", "origin": "🇮🇷 Iran", "type": "Espionage", "target": "Middle East", "tools": "DNS Tunneling, Karkoff"},
            {"name": "Agonizing Serpens", "origin": "🇮🇷 Iran", "type": "Wiper", "target": "Israel Education", "tools": "Multi-Layer Wipers"},
            {"name": "Lazarus", "origin": "🇰🇵 North Korea", "type": "Finance", "target": "Global", "tools": "Manuscrypt"},
            {"name": "APT28", "origin": "🇷🇺 Russia", "type": "Sabotage", "target": "NATO", "tools": "X-Agent"}
        ]

def save_reports(raw, analyzed):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        cnt = 0
        amap = {r['id']:r for r in analyzed if isinstance(r, dict)}
        
        for i, item in enumerate(raw):
            a = amap.get(i, {})
            try:
                c.execute("INSERT OR IGNORE INTO intel_reports (timestamp,published_at,source,url,title,category,severity,impact,summary) VALUES (?,?,?,?,?,?,?,?,?)",
                    (datetime.datetime.now(IL_TZ).isoformat(), item['date'], item['source'], item['url'], item['title'], 
                     a.get('category', 'General'), a.get('severity', 'Medium'), a.get('impact', 'Info'), a.get('summary', item['summary'])))
                if c.rowcount > 0: cnt += 1
            except: pass
        conn.commit()
        conn.close()
        return cnt
    except: return 0
