import os
import sqlite3
import asyncio
import aiohttp
import json
import datetime
from bs4 import BeautifulSoup
from dateutil import parser
from langchain_google_genai import ChatGoogleGenerativeAI

DB_NAME = "cti_war_room.db"

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
    # Clean records older than 24h to keep it fresh
    limit = (datetime.datetime.now() - datetime.timedelta(hours=24)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE published_at < ?", (limit,))
    conn.commit()
    conn.close()

class CTICollector:
    # 7 Professional Sources (3 Israel-Focused)
    SOURCES = [
        {"name": "CheckPoint Research", "url": "https://research.checkpoint.com/feed/", "type": "rss"},
        {"name": "ClearSky Security", "url": "https://www.clearskysec.com/feed/", "type": "rss"},
        {"name": "Israel Defense", "url": "https://www.israeldefense.co.il/en/rss.xml", "type": "rss"},
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "Bleeping Computer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"}
    ]

    async def fetch_source(self, session, source):
        headers = {'User-Agent': 'Mozilla/5.0 SOC-War-Room-Collector'}
        try:
            async with session.get(source['url'], headers=headers, timeout=10) as resp:
                if source['type'] == 'rss':
                    soup = BeautifulSoup(await resp.text(), 'xml')
                    items = []
                    for i in soup.find_all('item')[:10]:
                        items.append({
                            "title": i.title.text,
                            "url": i.link.text,
                            "date": parser.parse(i.pubDate.text).isoformat() if i.pubDate else datetime.datetime.now().isoformat(),
                            "source": source['name'],
                            "raw_content": i.description.text if i.description else i.title.text
                        })
                    return items
                elif source['type'] == 'json':
                    data = await resp.json()
                    return [{"title": v['cveID'], "url": source['url'], "date": datetime.datetime.now().isoformat(), "source": source['name'], "raw_content": v['vulnerabilityName']} for v in data.get('vulnerabilities', [])[:10]]
        except: return []

class AIBatchProcessor:
    def __init__(self, api_key):
        self.llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", google_api_key=api_key)
        self.categories = ["Phishing", "Vulnerability", "Research", "Israel Focus", "Malware", "DDoS", "Data Leak", "Defacement", "General"]

    async def analyze_batch(self, items):
        if not items: return []
        # Efficiency: Sending 10 items per batch to stay under 60s total time
        batch_text = "\n".join([f"ID:{i} | Title:{item['title']} | Content:{item['raw_content'][:200]}" for i, item in enumerate(items)])
        prompt = f"""
        Analyze these Cyber Intel items for a SOC Team.
        Rules:
        1. Classify into: {self.categories}.
        2. Use 'Israel Focus' if the target or context is Israel/Hebrew.
        3. If it's marketing or non-security, return "category": "IGNORE".
        4. Summarize in 1 technical English sentence.
        
        Data:
        {batch_text}
        
        Return ONLY a JSON array: [{{"id": 0, "category": "...", "country": "...", "summary": "..."}}, ...]
        """
        try:
            response = await self.llm.ainvoke(prompt)
            clean_res = response.content.replace('```json', '').replace('```', '').strip()
            return json.loads(clean_res)
        except: return []
