import os
import sqlite3
import asyncio
import aiohttp
import json
import datetime
import ssl
from bs4 import BeautifulSoup
from dateutil import parser
from langchain_google_genai import ChatGoogleGenerativeAI
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
        country TEXT,
        summary TEXT
    )''')
    conn.commit()
    conn.close()

class CTICollector:
    SOURCES = [
        {"name": "CheckPoint", "url": "https://research.checkpoint.com/feed/", "type": "rss"},
        {"name": "HackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"}
    ]

    async def fetch_item(self, session, source):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        try:
            print(f"Fetching {source['name']}...")
            async with session.get(source['url'], headers=headers, timeout=10) as resp:
                if resp.status != 200:
                    return []
                
                if source['type'] == 'rss':
                    text = await resp.text()
                    soup = BeautifulSoup(text, 'xml')
                    items = []
                    for i in soup.find_all('item')[:5]:
                        date_str = i.pubDate.text if i.pubDate else datetime.datetime.now().isoformat()
                        try:
                            dt = parser.parse(date_str).isoformat()
                        except:
                            dt = datetime.datetime.now().isoformat()
                            
                        items.append({
                            "title": i.title.text,
                            "url": i.link.text,
                            "date": dt,
                            "source": source['name'],
                            "raw_content": i.description.text if i.description else i.title.text
                        })
                    return items
                elif source['type'] == 'json':
                    data = await resp.json()
                    return [{"title": v['cveID'], "url": "https://cisa.gov", "date": datetime.datetime.now().isoformat(), "source": source['name'], "raw_content": v['vulnerabilityName']} for v in data.get('vulnerabilities', [])[:5]]
        except Exception as e:
            print(f"Error fetching {source['name']}: {e}")
            return []

    async def get_all_data(self):
        # SSL Context to prevent certificate errors
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.fetch_item(session, src) for src in self.SOURCES]
            results = await asyncio.gather(*tasks)
            return [item for sublist in results for item in sublist]

class AIBatchProcessor:
    def __init__(self, api_key):
        self.api_key = api_key
        # רשימת מודלים לניסיון לפי סדר עדיפות (מהיר -> יציב)
        self.models_to_try = ["gemini-1.5-flash-latest", "gemini-pro"]
        self.categories = ["Phishing", "Vulnerability", "Research", "Israel Focus", "Malware", "DDoS", "General"]

    async def analyze_batch(self, items):
        if not items: return []
        
        batch_text = "\n".join([f"ID:{i} | Title:{item['title']}" for i, item in enumerate(items)])
        prompt = f"""
        Categorize these cyber threats.
        Categories: {self.categories}.
        Rules:
        1. JSON Array ONLY.
        2. 'Israel Focus' if specific to Israel.
        3. 'IGNORE' if marketing.
        
        Items:
        {batch_text}
        
        Output: [{{"id": 0, "category": "...", "country": "...", "summary": "..."}}]
        """

        # ניסיון חכם: מנסה את המודל המהיר, אם נכשל עובר למודל היציב
        for model_name in self.models_to_try:
            try:
                print(f"Trying AI model: {model_name}...")
                llm = ChatGoogleGenerativeAI(model=model_name, google_api_key=self.api_key)
                response = await llm.ainvoke(prompt)
                clean_res = response.content.replace('```json', '').replace('```', '').strip()
                return json.loads(clean_res)
            except Exception as e:
                print(f"Model {model_name} failed: {e}")
                continue # נסה את המודל הבא ברשימה
        
        st.error("All AI models failed. Check API Key permissions.")
        return []

def save_reports(raw_items, analysis_results):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        analysis_map = {res['id']: res for res in analysis_results if res.get('category') != 'IGNORE'}
        count = 0
        for i, item in enumerate(raw_items):
            if i in analysis_map:
                ans = analysis_map[i]
                c.execute("INSERT OR IGNORE INTO intel_reports (timestamp, published_at, source, url, title, category, country, summary) VALUES (?,?,?,?,?,?,?,?)",
                        (datetime.datetime.now().isoformat(), item['date'], item['source'], item['url'], item['title'], ans['category'], ans['country'], ans['summary']))
                if c.rowcount > 0: count += 1
        conn.commit()
        conn.close()
        return count
    except Exception as e:
        print(f"DB Error: {e}")
        return 0
