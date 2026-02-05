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
    c.execute("CREATE INDEX IF NOT EXISTS idx_title ON intel_reports(title)")
    
    # Clean old data but keep INCD and DeepWeb scans longer
    limit_regular = (datetime.datetime.now(IL_TZ) - datetime.timedelta(hours=48)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE source NOT IN ('INCD', 'DeepWeb') AND published_at < ?", (limit_regular,))
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
    def scan_actor(self, actor_name, limit=5):
        """Searches the deep web for recent mentions of the actor"""
        results = []
        try:
            query = f'"{actor_name}" cyber threat intelligence malware analysis report'
            with DDGS() as ddgs:
                ddg_results = list(ddgs.text(query, max_results=limit))
                
                for res in ddg_results:
                    url = res.get('href')
                    if _is_url_processed(url): continue
                    
                    results.append({
                        "title": res.get('title'),
                        "url": url,
                        "date": datetime.datetime.now(IL_TZ).isoformat(),
                        "source": "DeepWeb",
                        "summary": res.get('body', 'No summary available.')
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
        You are a Senior CTI Analyst.
        Task: Process raw intelligence items.
        
        CRITICAL RULES:
        1. **DATE**: Return ISO 8601 format (YYYY-MM-DDTHH:MM:SS) based on the content.
        2. **CLEANUP**: Ignore "Menu", "Search", "Login", "Open article". Focus on the threat.
        3. **SUMMARY**: Write a professional 3-sentence summary (Attribution, TTPs, Impact).
        
        Return JSON: {"items": [{"id": 0, "category": "...", "severity": "...", "title": "...", "summary": "...", "published_at": "ISO_DATE"}]}
        """
        
        for i in range(0, len(items), chunk_size):
            chunk = items[i:i+chunk_size]
            
            batch_lines = []
            for idx, x in enumerate(chunk):
                # Clean specific noise before sending to AI
                clean_sum = x['summary'].replace('Open article on Malpedia', '').replace('\n', ' ').strip()
                limit = 4500 if x['source'] in ['Malpedia', 'DeepWeb'] else 500
                batch_lines.append(f"ID:{idx}|Src:{x['source']}|RawDate:{x['date']}|Content:{x['title']} - {clean_sum[:limit]}")

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
                
                txt = (chunk[j]['title'] + chunk[j]['summary']).lower()
                if 'apt' in txt or 'ransomware' in txt:
                    final_sev = 'High'

                results.append({
                    "category": final_cat, 
                    "severity": final_sev, 
                    "title": ai.get('title', chunk[j]['title']),
                    "summary": ai.get('summary', chunk[j]['summary'][:350]),
                    "published_at": ai.get('published_at', chunk[j]['date'])
                })
        return results

    async def analyze_single_ioc(self, ioc, ioc_type, data):
        lean_data = self._extract_key_intel(data)
        prompt = f"Analyze IOC: {ioc} ({ioc_type}). Context: {json.dumps(lean_data)}. Provide operational verdict, defense playbook, and technical context."
        return await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)

    async def generate_hunting_queries(self, actor):
        prompt = f"Generate Hunting Queries for Actor: {actor['name']}. Provide Google Chronicle (YARA-L) and Cortex XDR (XQL)."
        return await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)

class ThreatLookup:
    def __init__(self, vt_key=None, urlscan_key=None, abuse_key=None):
        self.vt_key, self.urlscan_key, self.abuse_key = vt_key, urlscan_key, abuse_key

    def query_virustotal(self, ioc, ioc_type):
        if not self.vt_key: return None
        try:
            endpoint = "urls" if ioc_type == "url" else "ip_addresses" if ioc_type == "ip" else "domains" if ioc_type == "domain" else "files"
            if ioc_type == "url": ioc = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            res = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}/{ioc}", headers={"x-apikey": self.vt_key}, timeout=15)
            return res.json().get('data', {}) if res.status_code == 200 else None
        except: return None

    def query_urlscan(self, ioc):
        if not self.urlscan_key: return None
        try:
            res = requests.get(f"https://urlscan.io/api/v1/search/?q={ioc}", headers={"API-Key": self.urlscan_key}, timeout=15)
            if res.json().get('results'):
                return requests.get(f"https://urlscan.io/api/v1/result/{res.json()['results'][0]['_id']}/", headers={"API-Key": self.urlscan_key}, timeout=15).json()
            return None
        except: return None

    def query_abuseipdb(self, ip):
        if not self.abuse_key: return None
        try:
            res = requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': self.abuse_key}, params={'ipAddress': ip}, timeout=10)
            return res.json().get('data', {})
        except: return None

# --- STRATEGIC INTEL & TOOLS ---
class AnalystToolkit:
    @staticmethod
    def get_tools():
        return {
            "Analysis": [{"name": "CyberChef", "url": "https://gchq.github.io/CyberChef/", "desc": "Decoding."}],
            "Reputation": [{"name": "VirusTotal", "url": "https://www.virustotal.com/", "desc": "Reputation."}]
        }

class APTSheetCollector:
    def fetch_threats(self): 
        return [
            {"name": "MuddyWater", "origin": "Iran", "target": "Israel", "type": "Espionage", "tools": "PowerShell", "keywords": ["muddywater"], "desc": "MOIS affiliated.", "mitre": "T1059"},
            {"name": "OilRig (APT34)", "origin": "Iran", "target": "Israel", "type": "Espionage", "tools": "DNS Tunneling", "keywords": ["oilrig"], "desc": "Gov targeting.", "mitre": "T1071"}
        ]

class CTICollector:
    SOURCES = [
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "HackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        {"name": "Malpedia", "url": "https://malpedia.caad.fkie.fraunhofer.de/feeds/rss/latest", "type": "rss"},
        {"name": "INCD", "url": "https://www.gov.il/he/rss/news_list?officeId=4bcc13f5-fed6-4b8c-b8ee-7bf4a6bc81c8", "type": "rss"},
        {"name": "INCD", "url": "https://t.me/s/Israel_Cyber", "type": "telegram"} 
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
                    entries_to_check = feed.entries[:4] if is_incd else feed.entries[:10]
                    
                    for entry in entries_to_check:
                        pub_date = now
                        try:
                            if hasattr(entry, 'published_parsed') and entry.published_parsed:
                                pub_date = datetime.datetime(*entry.published_parsed[:6]).replace(tzinfo=pytz.utc).astimezone(IL_TZ)
                        except: pass
                        
                        if not is_incd and (now - pub_date).total_seconds() > (48 * 3600): continue
                        if _is_url_processed(entry.link): continue
                        
                        sum_text = BeautifulSoup(getattr(entry, 'summary', ''), "html.parser").get_text()[:600]
                        final_url = entry.link

                        # --- MALPEDIA CLEANUP ---
                        if source['name'] == 'Malpedia':
                            try:
                                # Hop 1: Malpedia Profile
                                async with session.get(entry.link, headers=HEADERS, timeout=10) as mal_resp:
                                    if mal_resp.status == 200:
                                        mal_html = await mal_resp.text()
                                        mal_soup = BeautifulSoup(mal_html, 'html.parser')
                                        
                                        target_link = None
                                        # Strategy A
                                        for a in mal_soup.find_all('a', href=True):
                                            if any(x in a.get_text().lower() for x in ["open article", "read report", "direct link"]):
                                                target_link = a['href']
                                                break
                                        
                                        if not target_link:
                                            main_area = mal_soup.find('div', class_='content') or mal_soup.body
                                            for a in main_area.find_all('a', href=True):
                                                if "malpedia" not in a['href'] and a['href'].startswith("http"):
                                                    target_link = a['href']
                                                    break

                                        if target_link:
                                            final_url = target_link
                                            async with session.get(target_link, headers=HEADERS, timeout=15) as ext_resp:
                                                if ext_resp.status == 200:
                                                    ext_html = await ext_resp.text()
                                                    ext_soup = BeautifulSoup(ext_html, 'html.parser')
                                                    
                                                    # Extract Date
                                                    extracted_date = None
                                                    scripts = ext_soup.find_all('script', type='application/ld+json')
                                                    for script in scripts:
                                                        try:
                                                            js = json.loads(script.string)
                                                            if isinstance(js, dict):
                                                                extracted_date = js.get('datePublished') or js.get('dateCreated')
                                                            elif isinstance(js, list):
                                                                for item in js:
                                                                    extracted_date = item.get('datePublished') or item.get('dateCreated')
                                                                    if extracted_date: break
                                                            if extracted_date: break
                                                        except: pass
                                                    
                                                    if not extracted_date:
                                                        for m in ext_soup.find_all('meta'):
                                                            if m.get('name') in ['article:published_time', 'date', 'pubdate']:
                                                                extracted_date = m.get('content')
                                                                break

                                                    if extracted_date:
                                                        try:
                                                            dt = date_parser.parse(extracted_date)
                                                            if not dt.tzinfo: dt = pytz.utc.localize(dt)
                                                            pub_date = dt.astimezone(IL_TZ)
                                                        except: pass

                                                    # CLEANUP
                                                    for bad in ext_soup(["header", "footer", "nav", "aside", "script", "style", "form", "iframe", "noscript"]):
                                                        bad.decompose()
                                                    
                                                    for bad_cls in ["menu", "navigation", "sidebar", "cookie", "banner", "search"]:
                                                        for tag in ext_soup.find_all(class_=re.compile(bad_cls, re.I)):
                                                            tag.decompose()

                                                    texts = []
                                                    content_root = ext_soup.find('article') or ext_soup.find('main') or ext_soup.body
                                                    h1 = ext_soup.find('h1')
                                                    if h1: texts.append(f"TITLE: {h1.get_text().strip()}")
                                                    for p in content_root.find_all(['p', 'h2', 'h3', 'li']):
                                                        t = p.get_text().strip()
                                                        if len(t) > 50 and "Open article" not in t: texts.append(t)
                                                    
                                                    scraped_text = ' '.join(texts)
                                                    if len(scraped_text) > 200:
                                                        sum_text = f"[SCRAPED_CONTENT] {scraped_text[:4000]}"

                            except Exception: pass 
                        
                        # Extra cleanup of "Open article" artifacts from any summary
                        sum_text = sum_text.replace("Open article on Malpedia", "").strip()

                        items.append({"title": entry.title, "url": final_url, "date": pub_date.isoformat(), "source": source['name'], "summary": sum_text})

                elif source['type'] == 'telegram':
                    soup = BeautifulSoup(content, 'html.parser')
                    for msg in soup.find_all('div', class_='tgme_widget_message_wrap')[-5:]:
                        text = msg.find('div', class_='tgme_widget_message_text')
                        if text:
                            pub_date = now
                            t_tag = msg.find('time')
                            if t_tag: pub_date = date_parser.parse(t_tag['datetime']).astimezone(IL_TZ)
                            items.append({"title": "INCD Alert", "url": source['url'], "date": pub_date.isoformat(), "source": "INCD", "summary": text.get_text()[:800]})
                            
        except Exception: pass
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
            # De-duplication check using Title + Source
            c.execute("SELECT id FROM intel_reports WHERE title = ? AND source = ? AND published_at > datetime('now', '-1 day')", (a['title'], item['source']))
            if c.fetchone(): continue
            
            final_date = a.get('published_at', item['date'])
            try:
                c.execute("INSERT OR IGNORE INTO intel_reports (timestamp,published_at,source,url,title,category,severity,summary) VALUES (?,?,?,?,?,?,?,?)",
                    (datetime.datetime.now(IL_TZ).isoformat(), final_date, item['source'], item['url'], a['title'], a['category'], a['severity'], a['summary']))
                if c.rowcount > 0: cnt += 1
            except: pass
    conn.commit()
    conn.close()
    return cnt
