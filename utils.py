import os
import sqlite3
import asyncio
import aiohttp
import json
import datetime
from bs4 import BeautifulSoup
from dateutil import parser
from langchain_google_genai import ChatGoogleGenerativeAI

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
        country TEXT,
        summary TEXT
    )''')
    # Clean records older than 24h
    limit = (datetime.datetime.now() - datetime.timedelta(hours=24)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE published_at < ?", (limit,))
    conn.commit()
    conn.close()

class CTICollector:
    SOURCES = [
        {"name": "CheckPoint Research", "url": "https://research.checkpoint.com/feed/", "type": "rss"},
        {"name": "ClearSky Security", "url": "https://www.clearskysec.com/feed/", "type": "rss"},
        {"name": "Israel Defense", "url": "https://www.israeldefense.co.il/en/rss.xml", "type": "rss"},
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        {"name": "Bleeping Computer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"}
    ]

    async def fetch_item(self, session, source):
        try:
            async with session.get(source['url'], timeout=10) as resp:
                if source['type'] == 'rss':
                    soup = BeautifulSoup(await resp.text(), 'xml')
                    return [{"title": i.title.text, "url": i.link.text, "date": parser.parse(i.pubDate.text).isoformat(), "source": source['name']} for i in soup.find_all('item')[:5]]
                elif source['type'] == 'json':
                    data = await resp.json()
                    return [{"title": v['cveID'], "url": "https://cisa.gov", "date": datetime.datetime.now().isoformat(), "source": source['name']} for v in data.get('vulnerabilities', [])[:5]]
        except: return []

    async def get_all_data(self):
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_item(session, src) for src in self.SOURCES]
            results = await asyncio.gather(*tasks)
            return [item for sublist in results for item in sublist]

class AIBatchProcessor:
    def __init__(self, api_key):
        self.llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", google_api_key=api_key)
        self.categories = ["Phishing", "Vulnerability", "Research", "Israel Focus", "Malware", "DDoS", "Data Leak", "Defacement", "General"]

    async def analyze_batch(self, items):
        if not items: return []
        # Batching 15 items in a single prompt for speed
        batch_text = "\n".join([f"ID:{i} | Title:{item['title']}" for i, item in enumerate(items)])
        prompt = f"""
        Act as a SOC Analyst. Categorize these items into: {self.categories}.
        Rules:
        1. Only return valid JSON array of objects.
        2. Filter out marketing/non-security news (return "category": "IGNORE").
        3. 'Israel Focus' is for news impacting Israel.
        
        Items:
        {batch_text}
        
        Output format: [{{"id": 0, "category": "...", "country": "...", "summary": "..."}}, ...]
        """
        try:
            response = await self.llm.ainvoke(prompt)
            clean_res = response.content.replace('```json', '').replace('```', '').strip()
            return json.loads(clean_res)
        except: return []

def save_reports(raw_items, analysis_results):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    analysis_map = {res['id']: res for res in analysis_results if res.get('category') != 'IGNORE'}
    for i, item in enumerate(raw_items):
        if i in analysis_map:
            ans = analysis_map[i]
            c.execute("INSERT OR IGNORE INTO intel_reports (timestamp, published_at, source, url, title, category, country, summary) VALUES (?,?,?,?,?,?,?,?)",
                      (datetime.datetime.now().isoformat(), item['date'], item['source'], item['url'], item['title'], ans['category'], ans['country'], ans['summary']))
    conn.commit()
    conn.close()
