import os
import sqlite3
import asyncio
import aiohttp
import json
import datetime
import ssl # הוספנו טיפול ב-SSL
from bs4 import BeautifulSoup
from dateutil import parser
from langchain_google_genai import ChatGoogleGenerativeAI
import streamlit as st # הוספנו כדי להציג שגיאות למסך

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
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"}
    ]

    async def fetch_item(self, session, source):
        # שינוי User-Agent כדי שלא יחסמו אותנו
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        try:
            print(f"Attempting to fetch: {source['name']}...") # לוג לטרמינל
            async with session.get(source['url'], headers=headers, timeout=15) as resp:
                if resp.status != 200:
                    print(f"❌ Error {source['name']}: Status {resp.status}")
                    return []
                
                if source['type'] == 'rss':
                    text = await resp.text()
                    soup = BeautifulSoup(text, 'xml')
                    items = []
                    for i in soup.find_all('item')[:5]:
                        items.append({
                            "title": i.title.text,
                            "url": i.link.text,
                            "date": parser.parse(i.pubDate.text).isoformat() if i.pubDate else datetime.datetime.now().isoformat(),
                            "source": source['name'],
                            "raw_content": i.description.text if i.description else i.title.text
                        })
                    print(f"✅ Success {source['name']}: Found {len(items)} items")
                    return items
                elif source['type'] == 'json':
                    data = await resp.json()
                    print(f"✅ Success {source['name']}: Found JSON items")
                    return [{"title": v['cveID'], "url": "https://cisa.gov", "date": datetime.datetime.now().isoformat(), "source": source['name'], "raw_content": v['vulnerabilityName']} for v in data.get('vulnerabilities', [])[:5]]
        except Exception as e:
            # כאן אנחנו תופסים את השגיאה ומדפיסים אותה!
            print(f"🔥 CRITICAL FAIL {source['name']}: {str(e)}")
            return []

    async def get_all_data(self):
        # ביטול בדיקת SSL למקרה שאתה מאחורי חומת אש
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE

        connector = aiohttp.TCPConnector(ssl=ssl_context)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.fetch_item(session, src) for src in self.SOURCES]
            results = await asyncio.gather(*tasks)
            flat_results = [item for sublist in results for item in sublist]
            
            if not flat_results:
                print("⚠️ WARNING: Total fetched items is 0!")
            
            return flat_results

class AIBatchProcessor:
    def __init__(self, api_key):
        self.llm = ChatGoogleGenerativeAI(model="gemini-1.5-flash", google_api_key=api_key)
        self.categories = ["Phishing", "Vulnerability", "Research", "Israel Focus", "Malware", "DDoS", "General"]

    async def analyze_batch(self, items):
        if not items: 
            print("No items to analyze.")
            return []
        
        print(f"Sending {len(items)} items to Gemini...")
        batch_text = "\n".join([f"ID:{i} | Title:{item['title']}" for i, item in enumerate(items)])
        prompt = f"""
        Act as a SOC Analyst. Categorize these items into: {self.categories}.
        Rules:
        1. Return JSON array ONLY.
        2. Filter marketing (category: IGNORE).
        3. 'Israel Focus' if context is Israel.
        
        Items:
        {batch_text}
        
        Output format: [{{"id": 0, "category": "...", "country": "...", "summary": "..."}}]
        """
        try:
            response = await self.llm.ainvoke(prompt)
            clean_res = response.content.replace('```json', '').replace('```', '').strip()
            return json.loads(clean_res)
        except Exception as e:
            print(f"🤖 AI ERROR: {str(e)}") # הדפסת שגיאת AI
            st.error(f"Gemini Error: {str(e)}") # הצגה למשתמש
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
        print(f"💾 Saved {count} new reports to DB")
    except Exception as e:
        print(f"Database Error: {e}")
