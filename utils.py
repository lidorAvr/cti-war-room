import os
import sqlite3
import json
import asyncio
import aiohttp
import feedparser
import datetime
import random
from typing import List, Optional
from pydantic import BaseModel, Field

# --- MODERN IMPORTS ---
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from bs4 import BeautifulSoup
import google.generativeai as genai

# --- 1. Database Setup (SQLite) ---
DB_NAME = "cti_war_room.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS intel_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source TEXT,
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

# --- 2. Data Models (Pydantic) ---
class CyberIntel(BaseModel):
    threat_actor: str = Field(default="Unknown", description="Name of the threat actor")
    attacker_origin: str = Field(default="XX", description="Country Code")
    victim_target: str = Field(default="Global", description="Target Country/Sector")
    attack_vector: str = Field(default="Unknown", description="Method of attack")
    cve_id: Optional[str] = Field(default=None, description="CVE ID") 
    is_zero_day: bool = Field(default=False, description="Zero day flag")
    status: str = Field(default="Unknown", description="Status")
    summary: str = Field(default="No summary available", description="Summary")

# --- 3. AI Analysis Engine ---
class IntelProcessor:
    def __init__(self, api_key):
        genai.configure(api_key=api_key)
        
        # CHANGED PRIORITY: forcing 1.5-flash which has the stable free tier
        priority_models = [
            "gemini-1.5-flash",
            "gemini-1.5-flash-latest",
            "gemini-1.5-flash-001",
            "gemini-pro"
        ]
        
        selected_model = "gemini-1.5-flash" # Default fallback
        
        try:
            # List available models
            my_models = [m.name for m in genai.list_models()]
            print(f"Available in Account: {my_models}")
            
            # Pick the first matching stable model
            for priority in priority_models:
                found = next((m for m in my_models if priority in m), None)
                if found:
                    selected_model = found
                    break
            
            print(f"FINAL SELECTED MODEL: {selected_model}")
            
        except Exception as e:
            print(f"Model selection error: {e}")

        self.llm = ChatGoogleGenerativeAI(
            model=selected_model, 
            temperature=0,
            google_api_key=api_key,
            convert_system_message_to_human=True
        )
        self.parser = PydanticOutputParser(pydantic_object=CyberIntel)

    def analyze_text(self, text_content: str, title: str) -> CyberIntel:
        template = """
        You are a Cyber Threat Intelligence Analyst. 
        Analyze the following raw cyber security report/feed item and extract structured intelligence.
        
        Title: {title}
        Content: {content}
        
        Extract the data exactly according to the requested format.
        If a field is not mentioned, infer it reasonably or use 'Unknown'/'XX'.
        CRITICAL: If the content mentions 'Israel', 'Zionist', 'Tel Aviv', or Israeli companies, 'victim_target' MUST be 'IL'.
        
        {format_instructions}
        """
        
        prompt = ChatPromptTemplate.from_template(template)
        safe_content = text_content[:4000] 
        
        messages = prompt.format_messages(
            title=title,
            content=safe_content,
            format_instructions=self.parser.get_format_instructions()
        )
        
        try:
            response = self.llm.invoke(messages)
            return self.parser.parse(response.content)
        except Exception as e:
            print(f"AI Analysis Error: {e}")
            return CyberIntel(
                threat_actor="Unknown", 
                attacker_origin="XX", 
                victim_target="Global", 
                attack_vector="Unknown", 
                is_zero_day=False, 
                status="Analysis Failed", 
                summary=f"AI Error: {str(e)[:50]}",
                cve_id=None
            )

    def check_campaign_correlation(self, actor: str, target: str) -> bool:
        if actor == "Unknown": return False
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            SELECT count(*) FROM intel_reports 
            WHERE threat_actor = ? AND victim_target = ? AND timestamp > date('now', '-7 days')
        ''', (actor, target))
        try:
            result = c.fetchone()
            count = result[0] if result else 0
        except:
            count = 0
        conn.close()
        return count > 0

    def save_intel(self, intel: CyberIntel, source: str, title: str):
        is_campaign = self.check_campaign_correlation(intel.threat_actor, intel.victim_target)
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            INSERT INTO intel_reports (timestamp, source, title, threat_actor, attacker_origin, 
            victim_target, attack_vector, cve_id, is_zero_day, status, summary, is_campaign)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.datetime.now().isoformat(), source, title, intel.threat_actor, 
            intel.attacker_origin, intel.victim_target, intel.attack_vector, 
            intel.cve_id, intel.is_zero_day, intel.status, intel.summary, is_campaign
        ))
        conn.commit()
        conn.close()

# --- 4. Async Data Collector ---
class DataCollector:
    RSS_FEEDS = [
        "https://feeds.feedburner.com/TheHackersNews",
        "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml",
        "https://unit42.paloaltonetworks.com/feed/",
    ]
    
    @staticmethod
    def clean_html(html_content):
        soup = BeautifulSoup(html_content, "html5lib")
        return soup.get_text(separator=' ', strip=True)

    async def fetch_feed(self, url, session):
        try:
            async with session.get(url, timeout=10) as response:
                content = await response.text()
                feed = feedparser.parse(content)
                return feed.entries[:2] 
        except Exception as e:
            print(f"Feed Error {url}: {e}")
            return []

    async def run_collection_cycle(self, api_key):
        if not api_key:
            return "No API Key"
            
        processor = IntelProcessor(api_key)
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_feed(url, session) for url in self.RSS_FEEDS]
            results = await asyncio.gather(*tasks)
            
            count = 0
            for feed_entries in results:
                for entry in feed_entries:
                    clean_desc = self.clean_html(getattr(entry, 'summary', '') + getattr(entry, 'description', ''))
                    intel = processor.analyze_text(clean_desc, entry.title)
                    processor.save_intel(intel, "RSS Feed", entry.title)
                    count += 1
        return f"Processed {count} new threats."

# --- 5. Geo Helper ---
COUNTRY_COORDS = {
    "US": [-95.7129, 37.0902], "CN": [104.1954, 35.8617], "RU": [105.3188, 61.5240],
    "IL": [34.8516, 31.0461], "IR": [53.6880, 32.4279], "KP": [127.5101, 40.3399],
    "UK": [-3.4360, 55.3781], "DE": [10.4515, 51.1657], "IN": [78.9629, 20.5937],
    "XX": [0, 0]
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
