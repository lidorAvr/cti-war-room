import os
import sqlite3
import asyncio
import aiohttp
import json
import datetime
import ssl
import requests
import pandas as pd
import io
import re
import base64
from bs4 import BeautifulSoup
from dateutil import parser
import google.generativeai as genai
import streamlit as st

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

# --- SOC Tools: IOC Extractor ---
class IOCExtractor:
    def extract(self, text):
        # Regex patterns for common IOCs
        ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        
        ips = list(set(re.findall(ipv4_pattern, text)))
        domains = list(set(re.findall(domain_pattern, text)))
        hashes = list(set(re.findall(md5_pattern, text) + re.findall(sha256_pattern, text)))
        
        return {"IPs": ips, "Domains": domains, "Hashes": hashes}

# --- SOC Tools: Universal Lookup (ThreatFox + URLhaus) ---
class ThreatLookup:
    def __init__(self):
        self.tf_url = "https://threatfox-api.abuse.ch/api/v1/"
        self.uh_url = "https://urlhaus-api.abuse.ch/v1/url/"

    def query_threatfox(self, ioc):
        # ThreatFox Free API (Search by IOC)
        payload = {"query": "search_ioc", "search_term": ioc}
        try:
            res = requests.post(self.tf_url, json=payload, timeout=5)
            if res.status_code == 200:
                data = res.json()
                return data.get("data", []) if data.get("query_status") == "ok" else []
            return []
        except: return []

    def query_urlhaus(self, url):
        # URLhaus Free API
        payload = {"url": url}
        try:
            res = requests.post(self.uh_url, data=payload, timeout=5)
            if res.status_code == 200:
                data = res.json()
                return data if data.get("query_status") == "ok" else None
            return None
        except: return None

# --- Existing Collectors (Feed, MITRE, Sheets) ---
class MitreCollector:
    def get_latest_updates(self):
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            resp = requests.get("https://attack.mitre.org/resources/updates/", headers=headers, timeout=5)
            soup = BeautifulSoup(resp.text, 'html.parser')
            update = soup.find('h2')
            if update:
                return {"title": update.text.strip(), "url": "https://attack.mitre.org" + (update.find('a')['href'] if update.find('a') else "")}
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
        try:
            res = requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': self.key}, params={'ipAddress': ip, 'maxAgeInDays': 90})
            return {"success": True, "data": res.json()['data']} if res.status_code==200 else {"error": res.text}
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

class AIBatchProcessor:
    def __init__(self, key):
        self.key = key
        genai.configure(api_key=key)
    async def analyze_batch(self, items):
        if not items: return []
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
