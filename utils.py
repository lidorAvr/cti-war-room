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
        summary TEXT
    )''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_url ON intel_reports(url)")
    
    # Strict cleanup: Delete anything older than 48 hours to keep the feed fresh
    limit_strict = (datetime.datetime.now(IL_TZ) - datetime.timedelta(hours=48)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE published_at < ?", (limit_strict,))
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

# --- DEEP WEB SCANNER (UPDATED WITH DATE FILTERING) ---
class DeepWebScanner:
    def scan_actor(self, actor_name, limit=3):
        """Searches for RECENT mentions only (Last 48 Hours logic applied)"""
        results = []
        now = datetime.datetime.now(IL_TZ)
        cutoff = now - datetime.timedelta(hours=48)
        
        try:
            query = f'"{actor_name}" cyber threat intelligence malware'
            with DDGS() as ddgs:
                # timelimit='w' -> Restrict search to last week to filter out old 2025/2024 data at source
                ddg_results = list(ddgs.text(query, max_results=limit, timelimit='w'))
                
                for res in ddg_results:
                    url = res.get('href')
                    body = res.get('body', '')
                    title = res.get('title', '')
                    
                    if _is_url_processed(url): continue
                    
                    # 1. Try to extract date from snippet text
                    pub_date = now 
                    found_date = False
                    try:
                        # Search for patterns like "2 days ago", "Feb 05, 2026", etc. in the body
                        # This is a heuristic attempt
                        match = date_parser.parse(body, fuzzy=True, default=now)
                        if match and match.year == now.year: # Basic sanity check
                             pub_date = match.astimezone(IL_TZ)
                             found_date = True
                    except: pass
                    
                    # 2. Strict Filtering: If we found a date and it's old -> SKIP
                    if found_date and pub_date < cutoff:
                        continue
                        
                    # 3. If no date found, we rely on 'timelimit=w', but explicitly mark it as recent check
                    # We only add it if we are fairly sure it's new.
                    
                    results.append({
                        "title": title,
                        "url": url,
                        "date": pub_date.isoformat(),
                        "source": "DeepWeb",
                        "summary": body
                    })
        except Exception as e:
            print(f"Deep Scan Error for {actor_name}: {e}")
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
    payload = {"model": model, "messages": [{"role": "user", "content": prompt}], "temperature": 0.3}
    if json_mode: payload["response_format"] = {"type": "json_object"}
    
    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(url, json=payload, headers=headers, timeout=30) as resp:
                data = await resp.json()
                if resp.status == 200: return data['choices'][0]['message']['content']
                return f"Error {resp.status}: {data.get('error', {}).get('message', 'Unknown error')}"
        except Exception as e: return f"Connection Error: {e}"

class AIBatchProcessor:
    def __init__(self, key):
        self.key = key
        
    def _prune_data(self, data, max_list_items=5):
        if isinstance(data, dict):
            new_data = {}
            for k, v in data.items():
                if k in ['icon', 'favicon', 'html', 'screenshot', 'raw_response', 'response_headers']:
                    continue
                new_data[k] = self._prune_data(v, max_list_items)
            return new_data
        elif isinstance(data, list):
            return [self._prune_data(i, max_list_items) for i in data[:max_list_items]]
        else:
            return data

    def _extract_key_intel(self, raw_data):
        summary = {}
        if 'virustotal' in raw_data and isinstance(raw_data['virustotal'], dict):
            vt = raw_data['virustotal']
            attrs = vt.get('attributes', {})
            rels = vt.get('relationships', {})
            summary['virustotal'] = {
                'reputation': attrs.get('reputation'),
                'stats': attrs.get('last_analysis_stats'),
                'tags': attrs.get('tags'),
                'country': attrs.get('country'),
                'asn': attrs.get('asn'),
                'as_owner': attrs.get('as_owner'),
                'passive_dns': [r.get('attributes', {}).get('host_name') for r in rels.get('resolutions', {}).get('data', [])[:10]],
                'contacted_urls': [u.get('context_attributes', {}).get('url') for u in rels.get('contacted_urls', {}).get('data', [])[:5]]
            }
        if 'urlscan' in raw_data and isinstance(raw_data['urlscan'], dict):
            us = raw_data['urlscan']
            summary['urlscan'] = {
                'verdict': us.get('verdict', {}).get('overall'),
                'country': us.get('page', {}).get('country'),
                'target': us.get('task', {}).get('url')
            }
        if 'abuseipdb' in raw_data and isinstance(raw_data['abuseipdb'], dict):
            ab = raw_data['abuseipdb']
            summary['abuseipdb'] = {
                'score': ab.get('abuseConfidenceScore'),
                'isp': ab.get('isp'),
                'usage': ab.get('usageType')
            }
        return summary

    async def analyze_batch(self, items):
        if not items: return []
        chunk_size = 10
        results = []
        
        system_instruction = """
        You are an expert CTI Analyst.
        Task: Analyze cyber news items.
        
        OUTPUT RULES:
        1. IF Source is 'INCD' (Israel National Cyber Directorate):
           - TITLE & SUMMARY: Must be in **Hebrew** (Professional, clear, no gibberish).
        2. IF Source is 'DeepWeb' or 'Malpedia':
           - CRITICAL: Verify the content is RECENT (Last 48 Hours). If the text mentions events from 2024 or 2025, prefix title with "[OLD]".
           - SEVERITY: If 'APT', 'Ransomware' or 'Zero-Day' -> 'High' or 'Critical'.
        3. GENERAL:
           - TITLE: Short, informative (Max 8 words).
           - SEVERITY: 'Critical', 'High', 'Medium', 'Low'.
        
        Return JSON: {"items": [{"id": 0, "category": "...", "severity": "...", "title": "...", "summary": "..."}]}
        """
        
        for i in range(0, len(items), chunk_size):
            chunk = items[i:i+chunk_size]
            
            batch_lines = []
            for idx, x in enumerate(chunk):
                limit = 2500 if x['source'] in ['Malpedia', 'DeepWeb'] else 400
                clean_sum = x['summary'].replace('\n', ' ').strip()[:limit]
                batch_lines.append(f"ID:{idx}|Src:{x['source']}|Original:{x['title']} - {clean_sum}")

            batch_text = "\n".join(batch_lines)
            prompt = f"{system_instruction}\nRaw Data:\n{batch_text}"
            
            res = await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=True)
            chunk_map = {}
            try:
                data = json.loads(res)
                for item in data.get("items", []): chunk_map[item.get('id')] = item
            except: pass
            
            for j in range(len(chunk)):
                ai = chunk_map.get(j, {})
                
                final_sev = ai.get('severity', 'Medium')
                final_cat = ai.get('category', 'News')
                
                results.append({
                    "category": final_cat, 
                    "severity": final_sev, 
                    "title": ai.get('title', chunk[j]['title']),
                    "summary": ai.get('summary', chunk[j]['summary'][:350])
                })
        return results

    async def analyze_single_ioc(self, ioc, ioc_type, data):
        lean_data = self._extract_key_intel(data)
        
        prompt = f"""
        Act as a Senior Tier 3 SOC Analyst.
        Your task is to provide an OPERATIONAL analysis for an Enterprise Environment.
        
        Target IOC: {ioc} ({ioc_type})
        Intelligence Summary: {json.dumps(lean_data)}
        
        Output Structure (Markdown, English Only):
        
        ### 🛡️ Operational Verdict
        * **Verdict**: [Malicious / Suspicious / Clean]
        * **Confidence**: [High / Medium / Low]
        * **Reasoning**: Briefly explain why based on the engines/data.
        
        ### 🏢 Enterprise Defense Playbook (Action Items)
        * **Network (Firewall/Proxy)**: specific rule to apply (e.g., Block Domain, Drop Traffic).
        * **Endpoint (EDR)**: What to hunt for? (e.g., "Search for process spawning cmd.exe connecting to this IP").
        * **SIEM / Log Analysis**: Provide a specific search concept (e.g., "Look for HTTP GET requests to...").
        * **Containment**: Immediate steps if traffic is seen.

        ### 🔬 Technical Context
        * Analyze the available attributes and relations.
        * If this is a known campaign (e.g., Lazarus, Emotet), mention it.
        * If clean, confirm it's a False Positive risk.
        """
        res = await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)
        if "Error" in res:
            return await query_groq_api(self.key, prompt, model="llama-3.1-8b-instant", json_mode=False)
        return res

    async def generate_hunting_queries(self, actor):
        prompt = f"""
        Generate Hunting Queries for Actor: {actor['name']}.
        Context: {actor.get('mitre', 'N/A')} | {actor.get('tools', 'N/A')}.
        Provide: 1. Google Chronicle (YARA-L) 2. Cortex XDR (XQL).
        Explain logic in English.
        """
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
            if res.status_code in [400, 403, 500, 504]:
                res = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}", headers={"x-apikey": self.vt_key}, timeout=15)
                if res.status_code == 200: return res.json().get('data', {})
            return None
        except: return None

    def query_urlscan(self, ioc):
        if not self.urlscan_key: return None
        try:
            search_query = ioc
            try:
                if "://" in ioc:
                    parsed = urlparse(ioc)
                    if parsed.netloc: search_query = f"domain:{parsed.netloc}"
            except: pass
            
            res = requests.get(f"https://urlscan.io/api/v1/search/?q={search_query}", headers={"API-Key": self.urlscan_key}, timeout=15)
            data = res.json()
            if data.get('results'):
                first_hit = data['results'][0]
                scan_uuid = first_hit.get('_id')
                if scan_uuid:
                    full_res = requests.get(f"https://urlscan.io/api/v1/result/{scan_uuid}/", headers={"API-Key": self.urlscan_key}, timeout=15)
                    if full_res.status_code == 200: return full_res.json()
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
                {"name": "CyberChef", "url": "https://gchq.github.io/CyberChef/", "desc": "The Swiss Army Knife of data decoding."},
                {"name": "Any.Run", "url": "https://app.any.run/", "desc": "Interactive Malware Sandbox."},
                {"name": "UnpacMe", "url": "https://www.unpac.me/", "desc": "Automated Malware Unpacking."},
                {"name": "Hybrid Analysis", "url": "https://www.hybrid-analysis.com/", "desc": "Free malware analysis service."}
            ],
            "Lookup & Reputation": [
                {"name": "VirusTotal", "url": "https://www.virustotal.com/", "desc": "Analyze suspicious files/URLs."},
                {"name": "AbuseIPDB", "url": "https://www.abuseipdb.com/", "desc": "Check IP reputation."},
                {"name": "URLScan.io", "url": "https://urlscan.io/", "desc": "Website scanner for suspicious URLs."},
                {"name": "Talos Reputation", "url": "https://talosintelligence.com/reputation_center", "desc": "Cisco Talos IP/Domain check."}
            ],
            "Intelligence & Frameworks": [
                {"name": "MITRE ATT&CK", "url": "https://attack.mitre.org/", "desc": "Knowledge base of adversary tactics."},
                {"name": "Malpedia", "url": "https://malpedia.caad.fkie.fraunhofer.de/", "desc": "Resource for rapid identification of malware."},
                {"name": "LOLBAS", "url": "https://lolbas-project.github.io/", "desc": "Living Off The Land Binaries and Scripts."},
                {"name": "AlienVault OTX", "url": "https://otx.alienvault.com/", "desc": "Open Threat Exchange community."}
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
                "keywords": ["muddywater", "static_kitten", "mercury", "ligolo", "screenconnect"],
                "desc": "MOIS-affiliated group targeting Israeli Gov and Infrastructure. Known for social engineering.", 
                "mitre": "T1059, T1105, T1566",
                "malpedia": "https://malpedia.caad.fkie.fraunhofer.de/actor/muddywater"
            },
            {
                "name": "OilRig (APT34)", 
                "origin": "Iran", 
                "target": "Israel / Middle East", 
                "type": "Espionage", 
                "tools": "DNS Tunneling, SideTwist, Karkoff", 
                "keywords": ["oilrig", "apt34", "helix_kitten", "cobalt_gypsy", "sidetwist", "karkoff"],
                "desc": "Sophisticated espionage targeting critical sectors (Finance, Energy, Gov).", 
                "mitre": "T1071.004, T1048, T1132",
                "malpedia": "https://malpedia.caad.fkie.fraunhofer.de/actor/oilrig"
            },
            {
                "name": "Agonizing Serpens", 
                "origin": "Iran", 
                "target": "Israel", 
                "type": "Destructive", 
                "tools": "Wipers (BiBiWiper), SQL Injection", 
                "keywords": ["agonizing serpens", "agrius", "bibiwiper", "bibi-linux", "moneybird"],
                "desc": "Destructive attacks masquerading as ransomware. Targeted Israeli education and tech sectors.", 
                "mitre": "T1485, T1486, T1190",
                "malpedia": "https://malpedia.caad.fkie.fraunhofer.de/actor/agonizing_serpens"
            },
            {
                "name": "Imperial Kitten", 
                "origin": "Iran", 
                "target": "Israel", 
                "type": "Espionage/Cyber-Enabled Influence", 
                "tools": "IMAPLoader, Standard Python Backdoors", 
                "keywords": ["imperial kitten", "tortoise shell", "imaploader", "yellow liderc"],
                "desc": "IRGC affiliated. Focus on transportation, logistics, and maritime.", 
                "mitre": "T1566, T1071, T1021",
                "malpedia": "https://malpedia.caad.fkie.fraunhofer.de/actor/imperial_kitten"
            }
        ]

class CTICollector:
    SOURCES = [
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "HackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        {"name": "Malpedia", "url": "https://malpedia.caad.fkie.fraunhofer.de/feeds/rss/latest", "type": "rss"},
        {"name": "INCD", "url": "https://www.gov.il/he/rss/news_list?officeId=4bcc13f5-fed6-4b8c-b8ee-7bf4a6bc81c8", "type": "rss"},
        {"name
