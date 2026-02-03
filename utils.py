import os
import sqlite3
import json
import asyncio
import aiohttp
import feedparser
import datetime
import re
from typing import List, Optional
from pydantic import BaseModel, Field

# --- MODERN IMPORTS ---
from langchain_google_genai import ChatGoogleGenerativeAI, HarmBlockThreshold, HarmCategory
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from bs4 import BeautifulSoup

# --- 1. Database Setup (SQLite) ---
# Changed DB name to force recreation with new schema (URL column)
DB_NAME = "cti_v2.db"

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

# --- 2. Data Models (Pydantic) ---
class CyberIntel(BaseModel):
    threat_actor: str = Field(description="Name of threat actor (e.g. APT28). If unknown, infer from context or use 'Unknown Threat Actor'")
    attacker_origin: str = Field(description="2-letter Country Code (e.g. CN, RU, IR, KP). If specific country unknown, infer based on actor name, or use 'XX'")
    victim_target: str = Field(description="Target Country (2-letter) or Sector. If Israel/Zionist mentioned -> 'IL'")
    attack_vector: str = Field(description="Specific method: Phishing, Ransomware, DDoS, SQLi, 0-day, Supply Chain.")
    cve_id: str = Field(default="N/A", description="CVE ID if exists, else 'N/A'") 
    is_zero_day: bool = Field(default=False, description="Is this a zero-day?")
    status: str = Field(default="Active", description="Active/Patched/POC")
    summary: str = Field(description="Concise executive summary (max 20 words).")

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

    def extract_fallback(self, text):
        """Emergency regex extractor if JSON fails"""
        return CyberIntel(
            threat_actor="Detected Actor",
            attacker_origin="XX",
            victim_target="Global",
            attack_vector="Cyber Attack",
            summary=text[:100] + "...",
            status="Active",
            cve_id="N/A"
        )

    def analyze_text(self, text_content: str, title: str) -> CyberIntel:
        if not text_content or len(text_content) < 30:
             return self.extract_fallback("Content too short")

        template = """
        Act as a Senior CTI Analyst. Extract technical intelligence from the text below.
        
        Title: {title}
        Text: {content}
        
        RULES:
        1. 'attacker_origin': MUST be a 2-letter code (CN, RU, IR, US). If unknown, guess based on actor name (e.g. Lazarus->KP, Bear->RU). Only use 'XX' if completely impossible.
        2. 'attack_vector': MUST be specific (e.g., 'Ransomware', 'Phishing', 'Vulnerability'). NEVER use 'Unknown'.
        3. 'victim_target': If 'Israel', 'Tel Aviv' or 'Jerusalem' is mentioned, set to 'IL'.
        
        {format_instructions}
        """
        
        prompt = ChatPromptTemplate.from_template(template)
        
        # Safe truncate
        safe_content = text_content[:3500]
        
        messages = prompt.format_messages(
            title=title,
            content=safe_content,
            format_instructions=self.parser.get_format_instructions()
        )
        
        try:
            response = self.llm.invoke(messages)
            # Clean potential markdown backticks from Gemini
            clean_json = response.content.replace("```json", "").replace("```", "").strip()
            
            # Parse
            try:
                return self.parser.parse(clean_json)
            except:
                # Retry parsing manually if Pydantic strict fails
                data = json.loads(clean_json)
                return CyberIntel(**data)
                
        except Exception as e:
            print(f"AI Parsing Failed: {e}")
            # Intelligent Fallback
            return CyberIntel(
                threat_actor="Unidentified Actor",
                attacker_origin="XX", 
                victim_target="Global", 
                attack_vector="Exploit/Malware", 
                is_zero_day=False, 
                status="Active", 
                summary=f"Automated extraction failed. Manual review required. (Ref: {title[:30]})",
                cve_id="N/A"
            )

    def check_campaign_correlation(self, actor: str, target: str) -> bool:
        if actor in ["Unknown", "Unidentified Actor"]: return False
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

    def save_intel(self, intel: CyberIntel, source: str, url: str, title: str):
        is_campaign = self.check_campaign_correlation(intel.threat_actor, intel.victim_target)
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute('''
            INSERT INTO intel_reports (timestamp, source, source_url, title, threat_actor, attacker_origin, 
            victim_target, attack_vector, cve_id, is_zero_day, status, summary, is_campaign)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            datetime.datetime.now().isoformat(), source, url, title, intel.threat_actor, 
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
        "https://www.cisa.gov/uscert/ncas/alerts.xml"
    ]
    
    @staticmethod
    def clean_html(html_content):
        soup = BeautifulSoup(html_content, "html5lib")
        return soup.get_text(separator=' ', strip=True)

    async def fetch_feed(self, url, session):
        try:
            async with session.get(url, timeout=15) as response:
                content = await response.text()
                feed = feedparser.parse(content)
                return feed.entries[:3] 
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
                    raw_text = getattr(entry, 'summary', '') + getattr(entry, 'description', '')
                    clean_desc = self.clean_html(raw_text)
                    link = getattr(entry, 'link', '#')
                    source_name = getattr(entry, 'source', {}).get('title', 'RSS Source')
                    
                    intel = processor.analyze_text(clean_desc, entry.title)
                    processor.save_intel(intel, source_name, link, entry.title)
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
