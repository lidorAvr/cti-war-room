import os
import sqlite3
import json
import asyncio
import aiohttp
import feedparser
import datetime
import time
from pydantic import BaseModel, Field

# --- IMPORTS ---
from langchain_google_genai import ChatGoogleGenerativeAI, HarmBlockThreshold, HarmCategory
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from bs4 import BeautifulSoup

# --- 1. Database Setup (SQLite) ---
DB_NAME = "cti_v3.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS intel_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source TEXT,
            source_url TEXT,
            title TEXT,
            threat_actor TEXT,
            attacker_origin TEXT,
            victim_target TEXT,
            attack_vector TEXT,
            cve_id TEXT,
            is_zero_day BOOLEAN,
            status TEXT,
            summary TEXT,
            is_campaign BOOLEAN
        )
    ''')
    conn.commit()
    conn.close()

def cleanup_old_data():
    """Deletes records older than 24 hours."""
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("DELETE FROM intel_reports WHERE timestamp < datetime('now', '-1 day')")
        conn.commit()
        conn.close()
    except Exception:
        pass

# --- 2. Data Models ---
class CyberIntel(BaseModel):
    threat_actor: str = Field(default="Unknown Group", description="Actor Name")
    attacker_origin: str = Field(default="XX", description="Country Code")
    victim_target: str = Field(default="Global", description="Target")
    attack_vector: str = Field(default="Cyber Attack", description="Method")
    cve_id: str = Field(default="N/A", description="CVE") 
    is_zero_day: bool = Field(default=False, description="Zero Day?")
    status: str = Field(default="Active", description="Status")
    summary: str = Field(default="Summary unavailable.", description="Summary")

# --- 3. AI Engine (Async) ---
class IntelProcessor:
    def __init__(self, api_key):
        self.llm = ChatGoogleGenerativeAI(
            model="models/gemini-flash-latest", 
            temperature=0,
            google_api_key=api_key,
            convert_system_message_to_human=True,
            safety_settings={
                HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
                HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
            }
        )
        self.parser = PydanticOutputParser(pydantic_object=CyberIntel)

    def extract_fallback(self, text, title):
        clean_summary = text[:200].replace("\n", " ").strip() + "..."
        return CyberIntel(
            threat_actor="Unattributed", attacker_origin="XX", victim_target="Global",
            attack_vector="General Threat", summary=clean_summary, status="Active", cve_id="N/A"
        )

    async def analyze_text_async(self, text_content: str, title: str) -> CyberIntel:
        """Fully Async AI Analysis"""
        if not text_content or len(text_content) < 20:
             return self.extract_fallback(title, title)

        template = """
        Analyze Cyber Intelligence. Title: {title}. Text: {content}.
        Extract JSON:
        - threat_actor: Group/Nation or 'Unknown'.
        - attacker_origin: 2-letter Country Code (CN, RU, IR, KP, US, IL) or 'XX'.
        - victim_target: Target Country/Sector. 'IL' if Israel mentioned.
        - attack_vector: Specific method (Ransomware, Phishing, etc).
        - summary: 1 sentence event summary.
        {format_instructions}
        """
        
        prompt = ChatPromptTemplate.from_template(template)
        # Limit text to speed up processing
        safe_content = text_content[:2000] 
        
        messages = prompt.format_messages(
            title=title, content=safe_content,
            format_instructions=self.parser.get_format_instructions()
        )
        
        try:
            # ASYNC INVOKE - The Speed Secret
            response = await self.llm.ainvoke(messages)
            clean_json = response.content.replace("```json", "").replace("```", "").strip()
            try:
                return self.parser.parse(clean_json)
            except:
                data = json.loads(clean_json)
                return CyberIntel(**data)
        except Exception:
            return self.extract_fallback(text_content, title)

    def save_intel(self, intel: CyberIntel, source: str, url: str, title: str):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT id FROM intel_reports WHERE title = ?", (title,))
        if c.fetchone():
            conn.close()
            return 

        c.execute('''
            INSERT INTO intel_reports (timestamp, source, source_url, title, threat_actor, attacker_origin, 
            victim_target, attack_vector, cve_id, is_zero_day, status, summary, is_campaign)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.datetime.now().isoformat(), source, url, title, intel.threat_actor, 
            intel.attacker_origin, intel.victim_target, intel.attack_vector, 
            intel.cve_id, intel.is_zero_day, intel.status, intel.summary, False
        ))
        conn.commit()
        conn.close()

# --- 4. Turbo Data Collector ---
class DataCollector:
    RSS_FEEDS = [
        "https://feeds.feedburner.com/TheHackersNews",
        "https://unit42.paloaltonetworks.com/feed/",
        "https://www.recordedfuture.com/feed",
        "https://www.cisa.gov/uscert/ncas/alerts.xml",
        "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
        "https://research.checkpoint.com/feed/", 
        "https://www.clearskysec.com/feed/",
        "https://www.israeldefense.co.il/he/rss.xml"
    ]
    
    @staticmethod
    def clean_html(html_content):
        soup = BeautifulSoup(html_content, "html5lib")
        return soup.get_text(separator=' ', strip=True)

    async def fetch_feed(self, url, session):
        try:
            async with session.get(url, timeout=5) as response:
                content = await response.text()
                feed = feedparser.parse(content)
                # Return list of raw entries
                return [(entry, getattr(entry, 'source', {}).get('title', 'Web')) for entry in feed.entries[:3]]
        except:
            return []

    async def process_single_entry(self, processor, entry_tuple):
        entry, source_name = entry_tuple
        raw_text = getattr(entry, 'summary', '') + getattr(entry, 'description', '')
        clean_desc = self.clean_html(raw_text)
        link = getattr(entry, 'link', '#')
        
        # Parallel AI Call
        intel = await processor.analyze_text_async(clean_desc, entry.title)
        processor.save_intel(intel, source_name, link, entry.title)
        return 1

    async def run_collection_cycle(self, api_key):
        if not api_key: return "No API Key"
        cleanup_old_data()
        
        processor = IntelProcessor(api_key)
        async with aiohttp.ClientSession() as session:
            # 1. Fetch all feeds in parallel
            fetch_tasks = [self.fetch_feed(url, session) for url in self.RSS_FEEDS]
            feeds_results = await asyncio.gather(*fetch_tasks)
            
            # 2. Flatten list of all articles
            all_entries = [item for sublist in feeds_results for item in sublist]
            
            # 3. Analyze all articles in parallel (The Turbo Boost)
            analysis_tasks = [self.process_single_entry(processor, item) for item in all_entries]
            if analysis_tasks:
                await asyncio.gather(*analysis_tasks)
                
        return f"⚡ Scanned {len(all_entries)} threats in parallel."

# --- 5. Geo Helper ---
COUNTRY_COORDS = {
    "US": [-95.7129, 37.0902], "CN": [104.1954, 35.8617], "RU": [105.3188, 61.5240],
    "IL": [34.8516, 31.0461], "IR": [53.6880, 32.4279], "KP": [127.5101, 40.3399],
    "UK": [-3.4360, 55.3781], "DE": [10.4515, 51.1657], "IN": [78.9629, 20.5937],
    "XX": [0, 0], "Global": [0, 20]
}

def get_coords(code):
    return COUNTRY_COORDS.get(code, [0, 0])

def get_all_intel():
    conn = sqlite3.connect(DB_NAME)
    import pandas as pd
    try:
        df = pd.read_sql_query("SELECT * FROM intel_reports ORDER BY id DESC", conn)
    except:
        df = pd.DataFrame()
    conn.close()
    return df
