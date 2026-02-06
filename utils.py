import sqlite3
import asyncio
import aiohttp
import json
import datetime
import requests
import pandas as pd
import re
import ipaddress
import pytz
import feedparser
import base64
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from dateutil import parser as date_parser
from ddgs import DDGS
import google.generativeai as genai
import streamlit as st

DB_NAME = "cti_dashboard.db"
IL_TZ = pytz.timezone('Asia/Jerusalem')

# --- HTTP HEADERS ---
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9,he;q=0.8',
    'Referer': 'https://www.google.com/'
}

# --- IOC VALIDATION ---
def identify_ioc_type(ioc):
    ioc = ioc.strip()
    if re.match(r'^https?://', ioc) or re.match(r'^www\.', ioc):
        return "url"
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass
    if re.match(r'^[a-fA-F0-9]{32}$', ioc) or re.match(r'^[a-fA-F0-9]{40}$', ioc) or re.match(r'^[a-fA-F0-9]{64}$', ioc):
        return "hash"
    if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', ioc):
        return "domain"
    return None

# --- DATABASE MANAGEMENT ---
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
        severity TEXT,
        summary TEXT,
        actor_tag TEXT
    )''') # Added actor_tag column for deep scan association
    c.execute("CREATE INDEX IF NOT EXISTS idx_url ON intel_reports(url)")
    
    # Clean old data but keep INCD and DeepWeb scans longer
    limit_regular = (datetime.datetime.now(IL_TZ) - datetime.timedelta(hours=48)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE source NOT IN ('INCD', 'DeepWeb') AND published_at < ?", (limit_regular,))
    
    # Migration helper (if table exists without actor_tag)
    try:
        c.execute("ALTER TABLE intel_reports ADD COLUMN actor_tag TEXT")
    except:
        pass

    conn.commit()
    conn.close()

def _is_url_processed(url):
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT id FROM intel_reports WHERE url = ?", (url,))
        result = c.fetchone()
        conn.close()
        return result is not None
    except: return False

# --- DEEP WEB SCANNER ---
class DeepWebScanner:
    def scan_actor(self, actor_name, limit=3):
        """Searches the deep web for recent mentions of the actor"""
        results = []
        try:
            # Using specific query to reduce noise
            query = f'"{actor_name}" cyber threat intelligence malware analysis report'
            with DDGS() as ddgs:
                ddg_results = list(ddgs.text(query, max_results=limit))
                
                for res in ddg_results:
                    url = res.get('href')
                    if _is_url_processed(url): continue
                    
                    results.append({
                        "title": res.get('title'),
                        "url": url,
                        "date": datetime.datetime.now(IL_TZ).isoformat(), # Will be updated by AI extracted date later
                        "source": "DeepWeb",
                        "summary": res.get('body', 'No summary available.'),
                        "actor_tag": actor_name
                    })
        except Exception as e:
            print(f"Deep Scan Error: {e}")
        return results

# --- CONNECTION & AI ENGINES ---
class ConnectionManager:
    @staticmethod
    def check_groq(key):
        if not key: return False, "Missing Key"
        if key.startswith("gsk_"): return True, "Connected"
        return False, "Invalid Format"

async def query_groq_api(api_key, prompt, model="llama-3.1-8b-instant", json_mode=True):
    if not api_key: return "Error: Missing API Key"
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.1} # Low temp for factual reporting
    if json_mode: payload["response_format"] = {"type": "json_object"}
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, json=payload, headers=headers, timeout=40) as resp:
                data = await resp.json()
                if resp.status == 200: return data['choices'][0]['message']['content']
                return f"Error {resp.status}: {data.get('error', {}).get('message', 'Unknown error')}"
        except Exception as e: return f"Connection Error: {e}"

def translate_with_gemini_hebrew(text_content):
    """
    Translates technical cyber content to Hebrew using Gemini.
    Maintains technical terms in English.
    """
    try:
        google_key = st.secrets.get("google_key")
        if not google_key:
            return text_content + " (Gemini Key Missing)"
        
        genai.configure(api_key=google_key)
        model = genai.GenerativeModel('gemini-pro')
        
        prompt = f"""
        You are an expert translator for the Israeli National Cyber Directorate.
        
        TASK: Translate the following Cyber Threat Intelligence summary to **Hebrew**.
        
        RULES:
        1. **Style**: Formal, military/official tone (שפה רשמית, צבאית/ממשלתית).
        2. **Terminology**: DO NOT translate technical terms. Keep them in English.
           - Example: Ransomware -> Ransomware (not כופרה)
           - Example: Vulnerability -> Vulnerability (or חולשה, but keep CVEs in English)
           - Example: Exploit, Phishing, C2, Backdoor, CVSS, CVE -> KEEP IN ENGLISH.
        3. **Clarity**: The Hebrew must be native and professional.
        4. **Formatting**: Return ONLY the translated text.
        
        INPUT TEXT:
        {text_content}
        """
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        return text_content # Fallback to English on error

class AIBatchProcessor:
    def __init__(self, key):
        self.key = key
        
    async def analyze_batch(self, items):
        if not items: return []
        chunk_size = 5 # Reduced chunk size for better quality
        results = []
        
        # --- GROQ PROMPT: Professional, CVE Focused ---
        system_instruction = """
        You are an elite Cyber Threat Intelligence Analyst.
        
        TASK: Analyze the provided cyber security news items.
        
        OUTPUT FORMAT (JSON):
        {
            "items": [
                {
                    "id": 0,
                    "title": "FORMAL MILITARY STYLE TITLE (Include CVE if present)",
                    "summary": "Strict 3-4 sentence technical summary. MUST mention: Threat Actor, CVE ID (if any), CVSS Score (if any), and specific Impact. Tone: Official, concise.",
                    "severity": "Critical/High/Medium/Low",
                    "category": "Malware/Vulnerability/Phishing/News",
                    "published_at": "ISO8601 Date (YYYY-MM-DDTHH:MM:SS) extracted from text context"
                }
            ]
        }
        
        INSTRUCTIONS:
        1. **Date Extraction**: Look for "Published on:...", "Yesterday", "2 hours ago". Calculate or extract the exact date. If unsure, use the provided RawDate.
        2. **Severity**: If CVE > 9.0 or Ransomware or APT -> Critical/High.
        3. **Content**: No fluff. Pure intelligence.
        """
        
        for i in range(0, len(items), chunk_size):
            chunk = items[i:i+chunk_size]
            
            batch_lines = []
            for idx, x in enumerate(chunk):
                limit = 3000 
                clean_sum = x['summary'].replace('\n', ' ').strip()[:limit]
                batch_lines.append(f"ID:{idx} | RawDate:{x['date']} | Content:{x['title']} - {clean_sum}")

            batch_text = "\n".join(batch_lines)
            prompt = f"{system_instruction}\nRaw Data:\n{batch_text}"
            
            # 1. Get English Analysis from GROQ
            res = await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=True)
            
            chunk_map = {}
            try:
                data = json.loads(res)
                for item in data.get("items", []): chunk_map[item.get('id')] = item
            except: pass
            
            # 2. Process and Translate with GEMINI
            for j in range(len(chunk)):
                ai = chunk_map.get(j, {})
                
                english_title = ai.get('title', chunk[j]['title'])
                english_summary = ai.get('summary', chunk[j]['summary'][:350])
                
                # Combine for translation to save calls, or translate separately. 
                # Translating summary is most important.
                hebrew_summary = translate_with_gemini_hebrew(english_summary)
                
                # Basic Hebrew title adjustment (optional, or translate full title)
                hebrew_title = translate_with_gemini_hebrew(english_title)

                results.append({
                    "category": ai.get('category', 'News'), 
                    "severity": ai.get('severity', 'Medium'), 
                    "title": hebrew_title,
                    "summary": hebrew_summary,
                    "published_at": ai.get('published_at', chunk[j]['date']),
                    "actor_tag": chunk[j].get('actor_tag', None)
                })
        return results

    async def analyze_single_ioc(self, ioc, ioc_type, data):
        # Existing Logic kept as is, but could be enhanced with Hebrew if needed.
        # Keeping English for Forensics is usually preferred by analysts.
        # Minimal changes here to avoid breaking logic.
        lean_data = self._extract_key_intel(data)
        prompt = f"""
        Act as a Senior Tier 3 SOC Analyst.
        Target IOC: {ioc} ({ioc_type})
        Intelligence Summary: {json.dumps(lean_data)}
        
        Output Structure (Markdown, English Only):
        ### 🛡️ Operational Verdict
        * **Verdict**: [Malicious / Suspicious / Clean]
        * **Confidence**: [High / Medium / Low]
        * **Reasoning**: Briefly explain why based on the engines/data.
        ### 🏢 Enterprise Defense Playbook
        * **Network**: specific rule.
        * **Endpoint**: What to hunt for.
        """
        res = await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)
        return res

    def _extract_key_intel(self, raw_data):
        summary = {}
        if 'virustotal' in raw_data and isinstance(raw_data['virustotal'], dict):
            vt = raw_data['virustotal']
            attrs = vt.get('attributes', {})
            summary['virustotal'] = {
                'stats': attrs.get('last_analysis_stats'),
                'country': attrs.get('country'),
                'reputation': attrs.get('reputation')
            }
        return summary

    async def generate_hunting_queries(self, actor):
        prompt = f"Generate Hunting Queries for Actor: {actor['name']}. Tools: {actor.get('tools')}. Format: XQL, YARA."
        return await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)

class ThreatLookup:
    def __init__(self, vt_key=None, urlscan_key=None, abuse_key=None):
        self.vt_key, self.urlscan_key, self.abuse_key = vt_key, urlscan_key, abuse_key

    def query_virustotal(self, ioc, ioc_type):
        if not self.vt_key: return None
        try:
            if ioc_type == "url":
                url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
                endpoint = f"urls/{url_id}"
            else:
                endpoint = "ip_addresses" if ioc_type == "ip" else "domains" if ioc_type == "domain" else "files"
                endpoint = f"{endpoint}/{ioc}"
            
            params = {}
            if ioc_type in ['file', 'domain', 'ip', 'url']:
                params['relationships'] = 'contacted_urls,contacted_ips,contacted_domains,resolutions'
            
            res = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}", headers={"x-apikey": self.vt_key}, params=params, timeout=15)
            if res.status_code == 200: return res.json().get('data', {})
            return None
        except: return None

    def query_urlscan(self, ioc):
        if not self.urlscan_key: return None
        try:
            search_query = ioc
            res = requests.get(f"https://urlscan.io/api/v1/search/?q={search_query}", headers={"API-Key": self.urlscan_key}, timeout=15)
            data = res.json()
            if data.get('results'):
                return requests.get(f"https://urlscan.io/api/v1/result/{data['results'][0]['_id']}/", headers={"API-Key": self.urlscan_key}).json()
            return None
        except: return None

    def query_abuseipdb(self, ip):
        if not self.abuse_key: return None
        try:
            res = requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': self.abuse_key, 'Accept': 'application/json'}, params={'ipAddress': ip}, timeout=10)
            return res.json().get('data', {})
        except: return None

# --- STRATEGIC INTEL & TOOLS ---
class AnalystToolkit:
    @staticmethod
    def get_tools():
        return {
            "Analysis & Sandboxing": [
                {"name": "CyberChef", "url": "https://gchq.github.io/CyberChef/", "desc": "Decoding tools."},
                {"name": "Any.Run", "url": "https://app.any.run/", "desc": "Interactive Sandbox."}
            ],
            "Lookup": [
                {"name": "VirusTotal", "url": "https://www.virustotal.com/", "desc": "File/URL Analysis."},
                {"name": "AbuseIPDB", "url": "https://www.abuseipdb.com/", "desc": "IP Reputation."}
            ]
        }

class APTSheetCollector:
    def fetch_threats(self): 
        return [
            {
                "name": "MuddyWater", 
                "origin": "Iran", 
                "target": "Israel", 
                "type": "Espionage", 
                "tools": "PowerShell, ScreenConnect, Ligolo", 
                "keywords": ["muddywater", "static_kitten", "mercury", "ligolo"],
                "desc": "MOIS-affiliated group targeting Israeli Gov.", 
                "mitre": "T1059, T1105"
            },
            {
                "name": "OilRig (APT34)", 
                "origin": "Iran", 
                "target": "Israel", 
                "type": "Espionage", 
                "tools": "DNS Tunneling, Karkoff", 
                "keywords": ["oilrig", "apt34", "helix_kitten"],
                "desc": "Espionage targeting critical sectors.", 
                "mitre": "T1071.004, T1048"
            },
            {
                "name": "Agonizing Serpens", 
                "origin": "Iran", 
                "target": "Israel", 
                "type": "Destructive", 
                "tools": "Wipers (BiBiWiper)", 
                "keywords": ["agonizing serpens", "agrius", "bibiwiper"],
                "desc": "Destructive attacks disguised as ransomware.", 
                "mitre": "T1485, T1486"
            }
        ]

class CTICollector:
    SOURCES = [
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "TheHackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        {"name": "INCD", "url": "https://www.gov.il/he/rss/news_list?officeId=4bcc13f5-fed6-4b8c-b8ee-7bf4a6bc81c8", "type": "rss"}
    ]

    async def fetch_item(self, session, source):
        items = []
        try:
            async with session.get(source['url'], headers=HEADERS, timeout=25) as resp:
                if resp.status != 200: return []
                content = await resp.text()
                now = datetime.datetime.now(IL_TZ)
                
                is_incd = source['name'] == 'INCD'
                
                if source['type'] == 'rss':
                    feed = feedparser.parse(content)
                    entries_to_check = feed.entries[:5]
                    
                    for entry in entries_to_check:
                        pub_date = now
                        # FIX: Prioritize original published date
                        try:
                            if hasattr(entry, 'published_parsed') and entry.published_parsed:
                                pub_date = datetime.datetime(*entry.published_parsed[:6]).replace(tzinfo=pytz.utc).astimezone(IL_TZ)
                            elif hasattr(entry, 'updated_parsed') and entry.updated_parsed:
                                pub_date = datetime.datetime(*entry.updated_parsed[:6]).replace(tzinfo=pytz.utc).astimezone(IL_TZ)
                        except: pass
                        
                        if not is_incd and (now - pub_date).total_seconds() > (48 * 3600): continue
                        if _is_url_processed(entry.link): continue
                        
                        sum_text = BeautifulSoup(getattr(entry, 'summary', ''), "html.parser").get_text()[:600]
                        items.append({"title": entry.title, "url": entry.link, "date": pub_date.isoformat(), "source": source['name'], "summary": sum_text})

                elif source['type'] == 'json':
                     data = json.loads(content)
                     for v in data.get('vulnerabilities', [])[:5]:
                         url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?cve={v['cveID']}"
                         if _is_url_processed(url): continue
                         try: pub_date = date_parser.parse(v['dateAdded']).replace(tzinfo=IL_TZ)
                         except: pub_date = now
                         if (now - pub_date).total_seconds() > 172800: continue
                         items.append({"title": f"KEV: {v['cveID']}", "url": url, "date": pub_date.isoformat(), "source": "CISA", "summary": v.get('shortDescription')})
        except Exception as e: pass
        return items

    async def get_all_data(self):
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_item(session, s) for s in self.SOURCES]
            results = await asyncio.gather(*tasks)
            return [i for sub in results for i in sub]

def save_reports(raw, analyzed):
    conn = sqlite3.connect(DB_NAME)
    c, cnt = conn.cursor(), 0
    for i, item in enumerate(raw):
        if i < len(analyzed):
            a = analyzed[i]
            # Use AI Extracted date if valid, else original feed date
            final_date = a.get('published_at', item['date'])
            # Validation to ensure date format is correct
            try: date_parser.parse(final_date)
            except: final_date = item['date']

            try:
                c.execute("INSERT OR IGNORE INTO intel_reports (timestamp,published_at,source,url,title,category,severity,summary,actor_tag) VALUES (?,?,?,?,?,?,?,?,?)",
                    (datetime.datetime.now(IL_TZ).isoformat(), final_date, item['source'], item['url'], a['title'], a['category'], a['severity'], a['summary'], a.get('actor_tag')))
                if c.rowcount > 0: cnt += 1
            except: pass
    conn.commit()
    conn.close()
    return cnt
