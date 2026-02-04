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
    limit = (datetime.datetime.now() - datetime.timedelta(hours=24)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE published_at < ?", (limit,))
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
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        try:
            async with session.get(source['url'], headers=headers, timeout=10) as resp:
                if resp.status != 200: return []
                if source['type'] == 'rss':
                    soup = BeautifulSoup(await resp.text(), 'xml')
                    items = []
                    for i in soup.find_all('item')[:5]:
                        d = i.pubDate.text if i.pubDate else datetime.datetime.now().isoformat()
                        items.append({"title": i.title.text, "url": i.link.text, "date": d, "source": source['name'], "raw_content": i.description.text if i.description else i.title.text})
                    return items
                elif source['type'] == 'json':
                    data = await resp.json()
                    return [{"title": v['cveID'], "url": "https://cisa.gov", "date": datetime.datetime.now().isoformat(), "source": source['name'], "raw_content": v['vulnerabilityName']} for v in data.get('vulnerabilities', [])[:5]]
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
        
        # בניית הפרומפט
        batch_text = "\n".join([f"ID:{i} | Title:{item['title']}" for i, item in enumerate(items)])
        prompt = f"""
        Categorize these cyber threats for a SOC team.
        Categories: [Phishing, Vulnerability, Research, Israel Focus, Malware, DDoS, General].
        Rules:
        1. JSON Array ONLY. No markdown.
        2. 'Israel Focus' if context is Israel/Hebrew/Middle East.
        3. 'IGNORE' if marketing/sales.
        
        Items:
        {batch_text}
        
        Output: [{{"id": 0, "category": "...", "country": "...", "summary": "..."}}]
        """

        # רשימת המודלים המעודכנת לפי מה שזמין לך (2.5 ו-2.0)
        models_to_try = [
            "gemini-2.5-flash",       # המהיר והחדש ביותר
            "gemini-2.0-flash",       # יציב מאוד
            "gemini-flash-latest",    # מצביע תמיד לגרסה האחרונה
            "gemini-2.5-pro"          # חזק יותר (למקרה הצורך)
        ]

        for model_name in models_to_try:
            try:
                model = genai.GenerativeModel(model_name)
                # שימוש ב-generate_content הרגיל (יותר יציב מ-async בגרסאות מסוימות)
                response = await model.generate_content_async(prompt)
                
                clean_res = response.text.replace('```json', '').replace('```', '').strip()
                return json.loads(clean_res)
            except Exception as e:
                # מדלגים בשקט למודל הבא ברשימה
                continue
        
        st.error(f"❌ Failed to connect to Gemini 2.5/2.0 models.")
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
                c.execute("INSERT OR IGNORE INTO intel_reports (timestamp, published_at, source, url, title, category, country, summary) VALUES (?,?,?,?,?,?,?,?)",
                        (datetime.datetime.now().isoformat(), item['date'], item['source'], item['url'], item['title'], ans['category'], ans['country'], ans['summary']))
                if c.rowcount > 0: c_count += 1
        conn.commit()
        conn.close()
        return c_count
    except: return 0
