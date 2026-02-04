import os
import sqlite3
import asyncio
import aiohttp
import json
import datetime
import ssl
from bs4 import BeautifulSoup
from dateutil import parser
import google.generativeai as genai
import streamlit as st

DB_NAME = "cti_dashboard.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # הוספנו עמודות חדשות: severity, impact
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
    # מחיקת נתונים ישנים מ-24 שעות
    limit = (datetime.datetime.now() - datetime.timedelta(hours=24)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE published_at < ?", (limit,))
    conn.commit()
    conn.close()

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
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        try:
            async with session.get(source['url'], headers=headers, timeout=10) as resp:
                if resp.status != 200: return []
                
                # חישוב חלון זמנים של 24 שעות
                now = datetime.datetime.now(datetime.timezone.utc)
                last_24h = now - datetime.timedelta(hours=24)

                if source['type'] == 'rss':
                    soup = BeautifulSoup(await resp.text(), 'xml')
                    items = []
                    for i in soup.find_all('item')[:10]:
                        # פרסור תאריך קפדני
                        pub_date_str = i.pubDate.text if i.pubDate else str(now)
                        try:
                            pub_dt = parser.parse(pub_date_str)
                            # נרמול ל-UTC לצורך השוואה
                            if pub_dt.tzinfo is None:
                                pub_dt = pub_dt.replace(tzinfo=datetime.timezone.utc)
                            
                            # סינון: רק מה שב-24 שעות האחרונות
                            if pub_dt < last_24h:
                                continue
                            
                            final_date = pub_dt.isoformat()
                        except:
                            final_date = now.isoformat()

                        items.append({
                            "title": i.title.text,
                            "url": i.link.text,
                            "date": final_date,
                            "source": source['name'],
                            "raw_content": i.description.text if i.description else i.title.text
                        })
                    return items

                elif source['type'] == 'json':
                    data = await resp.json()
                    # CISA KEV usually doesn't have hour-level granularity, taking recent adds
                    return [{"title": f"KEV: {v['cveID']}", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "date": datetime.datetime.now().isoformat(), "source": source['name'], "raw_content": v['vulnerabilityName']} for v in data.get('vulnerabilities', [])[:3]]
        except: return []

    async def get_all_data(self):
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        conn = aiohttp.TCPConnector(ssl=ssl_ctx)
        async with aiohttp.ClientSession(connector=conn) as session:
            tasks = [self.fetch_item(session, src) for src in self.SOURCES]
            results = await asyncio.gather(*tasks)
            return [item for sublist in results for item in sublist]

class AIBatchProcessor:
    def __init__(self, api_key):
        self.api_key = api_key
        genai.configure(api_key=api_key)

    async def analyze_batch(self, items):
        if not items: return []
        
        batch_text = "\n".join([f"ID:{i} | Source: {item['source']} | Title:{item['title']}" for i, item in enumerate(items)])
        
        # פרומפט משופר לזיהוי ישראל וניתוח השפעה
        prompt = f"""
        You are an elite SOC Analyst. Analyze these items strictly.
        
        Fields required per item:
        1. "category": Choose ONE [Phishing, Vulnerability, Research, Israel Focus, Malware, DDoS, General].
        2. "severity": Choose ONE [Critical, High, Medium, Low].
        3. "impact": Short phrase on WHAT is affected (e.g., "Windows Servers", "Israeli Banks", "Android Users", "Global Logistics").
        4. "summary": 1 technical sentence.

        CRITICAL RULES:
        - IF Source is "ClearSky" OR "Israel Defense" -> Category MUST be "Israel Focus".
        - IF Title mentions "Israel", "Tel Aviv", "Gaza", "Iran", "Hamas" -> Category IS "Israel Focus".
        - IF Vulnerability is actively exploited (KEV) -> Severity IS "Critical".
        - Marketing/Sales junk -> "category": "IGNORE".

        Items:
        {batch_text}
        
        Output JSON Array: [{{"id": 0, "category": "...", "severity": "...", "impact": "...", "summary": "..."}}]
        """

        models_to_try = ["gemini-2.0-flash", "gemini-2.5-flash", "gemini-1.5-flash"]

        for model_name in models_to_try:
            try:
                model = genai.GenerativeModel(model_name)
                response = await model.generate_content_async(prompt)
                clean_res = response.text.replace('```json', '').replace('```', '').strip()
                return json.loads(clean_res)
            except: continue
        
        return []

def save_reports(raw_items, analysis_results):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        analysis_map = {res['id']: res for res in analysis_results if res.get('category') != 'IGNORE'}
        c_count = 0
        for i, item in enumerate(raw_items):
            if i in analysis_map:
                ans = analysis_map[i]
                c.execute("INSERT OR IGNORE INTO intel_reports (timestamp, published_at, source, url, title, category, severity, impact, summary) VALUES (?,?,?,?,?,?,?,?,?)",
                        (datetime.datetime.now().isoformat(), item['date'], item['source'], item['url'], item['title'], ans['category'], ans['severity'], ans['impact'], ans['summary']))
                if c.rowcount > 0: c_count += 1
        conn.commit()
        conn.close()
        return c_count
    except: return 0
