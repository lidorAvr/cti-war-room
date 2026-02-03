import os
import sqlite3
import json
import asyncio
import aiohttp
import feedparser
import datetime
import re
import time
from typing import List, Optional
from pydantic import BaseModel, Field

# --- IMPORTS ---
from langchain_google_genai import ChatGoogleGenerativeAI, HarmBlockThreshold, HarmCategory
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from bs4 import BeautifulSoup

# --- 1. Database Setup (SQLite) ---
DB_NAME = "cti_v3.db" # Changed to v3 to force clean slate

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
    """Deletes records older than 24 hours to keep the dashboard fresh."""
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        # Delete entries where timestamp is older than 1 day
        c.execute("DELETE FROM intel_reports WHERE timestamp < datetime('now', '-1 day')")
        deleted = c.rowcount
        conn.commit()
        conn.close()
        if deleted > 0:
            print(f"🧹 Cleaned up {deleted} old records.")
    except Exception as e:
        print(f"Cleanup Error: {e}")

# --- 2. Data Models (Pydantic) ---
class CyberIntel(BaseModel):
    threat_actor: str = Field(default="Unknown Group", description="Name of threat actor (e.g. APT28).")
    attacker_origin: str = Field(default="XX", description="2-letter Country Code (e.g. CN, RU, IR). If unknown, use 'XX'.")
    victim_target: str = Field(default="Global", description="Target Country (2-letter) or Sector.")
    attack_vector: str = Field(default="Cyber Attack", description="Specific method: Phishing, Ransomware, etc.")
    cve_id: str = Field(default="N/A", description="CVE ID if exists") 
    is_zero_day: bool = Field(default=False, description="Is this a zero-day?")
    status: str = Field(default="Active", description="Active/Patched")
    summary: str = Field(default="Details inside.", description="Concise summary.")

# --- 3. AI Analysis Engine ---
class IntelProcessor:
    def __init__(self, api_key):
        target_model = "models/gemini-flash-latest"
        
        self.llm = ChatGoogleGenerativeAI(
            model=target_model, 
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
        """
        NO ERROR MESSAGES ALLOWED.
        If AI fails, we manually extract a summary from the raw text.
        """
        clean_summary = text[:200].replace("\n", " ").strip() + "..."
        
        return CyberIntel(
            threat_actor="Unattributed",
            attacker_origin="XX",
            victim_target="Global",
            attack_vector="General Cyber Threat",
            summary=clean_summary, # Use real text!
            status="Active",
            cve_id="N/A"
        )

    def analyze_text(self, text_content: str, title: str) -> CyberIntel:
        if not text_content or len(text_content) < 20:
             return self.extract_fallback(title, title) # Use title as content if empty

        template = """
        Analyze this Cyber Security Intelligence.
        Title: {title}
        Text: {content}
        
        Extract these fields JSON format:
        - threat_actor: Specific group name or 'Unknown'.
        - attacker_origin: Country Code (CN, RU, IR, KP, US, IL). If unknown use 'XX'.
        - victim_target: Target Country Code or 'Global'. If Israel/Zionist mentioned -> 'IL'.
        - attack_vector: e.g. Ransomware, Phishing, DDoS, Vulnerability.
        - summary: A clear 1-sentence summary of the EVENT (not the article).
        
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
            clean_json = response.content.replace("```json", "").replace("```", "").strip()
            # Try parsing
            try:
                return self.parser.parse(clean_json)
            except:
                data = json.loads(clean_json)
                return CyberIntel(**data)
                
        except Exception as e:
            # SILENT FALLBACK - No error messages to user
            print(f"AI Logic Error: {e}")
            return self.extract_fallback(text_content, title)

    def save_intel(self, intel: CyberIntel, source: str, url: str, title: str):
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        # Avoid duplicates based on title
        c.execute("SELECT id FROM intel_reports WHERE title = ?", (title,))
        if c.fetchone():
            conn.close()
            return # Skip duplicate

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

# --- 4. Async Data Collector ---
class DataCollector:
    RSS_FEEDS = [
        # --- Requested Sources ---
        "https://feeds.feedburner.com/TheHackersNews",  # The Hacker News
        "https://unit42.paloaltonetworks.com/feed/",    # Palo Alto Unit 42 (Research)
        "https://www.recordedfuture.com/feed",          # Recorded Future (Research)
        "https://www.cisa.gov/uscert/ncas/alerts.xml",  # CISA Alerts
        "https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml", # Vulnerabilities
        
        # --- Israel Specific ---
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
            async with session.get(url, timeout=10) as response:
                content = await response.text()
                feed = feedparser.parse(content)
                return feed.entries[:4] # Take top 4 from each
        except Exception as e:
            return []

    async def run_collection_cycle(self, api_key):
        if not api_key: return "No API Key"
        
        # 1. Clean old data first
        cleanup_old_data()
        
        processor = IntelProcessor(api_key)
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_feed(url, session) for url in self.RSS_FEEDS]
            results = await asyncio.gather(*tasks)
            
            count = 0
            for feed_entries in results:
                for entry in feed_entries:
                    raw_text = getattr(entry, 'summary', '') + getattr(entry, 'description', '')
                    clean_desc = self.clean_html(raw_text)
                    link = getattr(entry, 'link', '#')
                    source_name = getattr(entry, 'source', {}).get('title', 'Web Source')
                    
                    # AI Analysis
                    intel = processor.analyze_text(clean_desc, entry.title)
                    processor.save_intel(intel, source_name, link, entry.title)
                    count += 1
        return f"Updated {count} intels."

# --- 5. Improved Map Coords ---
# Expanded list to ensure lines are drawn even for broad regions
COUNTRY_COORDS = {
    "US": [-95.7129, 37.0902], "CN": [104.1954, 35.8617], "RU": [105.3188, 61.5240],
    "IL": [34.8516, 31.0461], "IR": [53.6880, 32.4279], "KP": [127.5101, 40.3399],
    "UK": [-3.4360, 55.3781], "DE": [10.4515, 51.1657], "IN": [78.9629, 20.5937],
    "UA": [31.1656, 48.3794], "JP": [138.2529, 36.2048], "FR": [2.2137, 46.2276],
    "BR": [-51.9253, -14.2350], "CA": [-106.3468, 56.1304], "AU": [133.7751, -25.2744],
    "TR": [35.2433, 38.9637], "SA": [45.0792, 23.8859], "EG": [30.8025, 26.8206],
    "XX": [0, 0], # Unknown Origin (Null Island / Ocean center)
    "Global": [0, 20] # General Global Target
}

def get_coords(code):
    # Default to XX (0,0) if code not found, to allow line drawing
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
