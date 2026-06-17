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
import time
import logging
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from dateutil import parser as date_parser
from duckduckgo_search import DDGS
import streamlit as st
from difflib import SequenceMatcher
from fake_useragent import UserAgent

DB_NAME = "cti_dashboard.db"
IL_TZ = pytz.timezone('Asia/Jerusalem')

# --- CONFIGURATION ---
HISTORY_DAYS = 7    # טווח קשיח: שבוע אחרון בלבד
FETCH_LIMIT = 100   # מקסימום שאיבה מכל מקור

log = logging.getLogger("cti_war_room")


def get_secret(key, default=""):
    """Safe access to st.secrets that never raises when no secrets.toml exists.

    st.secrets.get(key, default) raises StreamlitSecretNotFoundError when there is
    no secrets file at all (the supplied default is never reached). This wraps it
    so a missing key OR a missing secrets file both return `default` — the app
    boots and simply reports the capability as disabled instead of crashing.
    """
    try:
        return st.secrets.get(key, default)
    except Exception:
        return default


# --- ROBUST HEADERS ---
def get_headers():
    try:
        ua = UserAgent()
        return {'User-Agent': ua.random, 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}
    except Exception as e:
        log.debug("fake-useragent unavailable, using static UA: %s", e)
        return {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}


def _entry_summary(entry):
    """Robustly extract an RSS entry's summary text. Some feeds (e.g. Dark
    Reading) omit `summary`; fall back to description/content so one feed's
    quirk never crashes the whole source."""
    raw = getattr(entry, 'summary', None) or getattr(entry, 'description', None)
    if not raw:
        content = getattr(entry, 'content', None)
        if content:
            try:
                first = content[0]
                raw = first.get('value') if hasattr(first, 'get') else getattr(first, 'value', None)
            except Exception:
                raw = None
    return BeautifulSoup(raw or "", "html.parser").get_text()[:2500]


# --- Feed quality: drop marketing/promo and off-topic items ---
# General tech/business outlets (not cyber-only): for these we require a
# cyber/threat keyword, so funding rounds / appointments / gadgets are dropped
# while real security stories pass. Dedicated CTI sources are trusted as-is.
GENERAL_SOURCES = {"People & Computers"}

MARKETING_MARKERS = (
    "תוכן שיווקי", "תוכן ממומן", "פרסום ממומן", "מעוניינים לפרסם", "לפרסום בערוץ",
    "לפרסום אצלנו", "sponsored", "advertorial", "promoted post",
)

CYBER_KEYWORDS = (
    "cyber", "hack", "attack", "malware", "ransomware", "phish", "vulnerab",
    "exploit", "breach", "threat", "cve-", "apt", "ddos", "botnet", "backdoor",
    "trojan", "zero-day", "zero day", "0day", "spyware", "stealer", "incident",
    "compromise", "data leak", "leaked", "patch", "security",
    "סייבר", "פריצה", "מתקפ", "תקיפ", "נוזק", "כופר", "פישינג", "פגיעות",
    "דליפ", "דלף", "האקר", "תוקף", "חדיר", "אבטח", "פוגען", "סחיטה", "הצפנ",
)


def is_noise(item):
    """True if a feed item should be dropped: marketing/promo (any source), or an
    off-topic story from a general-tech source (no cyber keyword)."""
    text = f"{item.get('title', '')} {item.get('summary', '')}".lower()
    if any(m in text for m in MARKETING_MARKERS):
        return True
    if item.get("source") in GENERAL_SOURCES and not any(k in text for k in CYBER_KEYWORDS):
        return True
    return False


def cap_per_source(df, n, source_col="source"):
    """Keep at most n rows per source (df assumed already sorted by recency) so
    high-volume feeds don't crowd out everyone else. Original order is preserved."""
    if df is None or df.empty:
        return df
    return df.groupby(source_col, group_keys=False, sort=False).head(n)

# --- DATE HELPER ---
def parse_flexible_date(date_obj):
    now = datetime.datetime.now(IL_TZ)
    try:
        if isinstance(date_obj, time.struct_time):
            dt = datetime.datetime(*date_obj[:6], tzinfo=pytz.utc)
            return dt.astimezone(IL_TZ).isoformat()
        if isinstance(date_obj, str):
            dt = date_parser.parse(date_obj)
            if dt.tzinfo is None: dt = pytz.utc.localize(dt)
            return dt.astimezone(IL_TZ).isoformat()
        if isinstance(date_obj, datetime.datetime):
            if date_obj.tzinfo is None: date_obj = pytz.utc.localize(date_obj)
            return date_obj.astimezone(IL_TZ).isoformat()
    except Exception as e:
        log.debug("parse_flexible_date failed for %r: %s", date_obj, e)
    return now.isoformat()

def is_recent(date_str):
    """Checks if an ISO date string is within the HISTORY_DAYS window."""
    try:
        dt = date_parser.parse(date_str)
        if dt.tzinfo is None: dt = pytz.utc.localize(dt)
        limit = datetime.datetime.now(dt.tzinfo) - datetime.timedelta(days=HISTORY_DAYS)
        return dt > limit
    except Exception as e:
        log.debug("is_recent could not parse %r: %s", date_str, e)
        return True  # If unsure, keep it

# --- IOC VALIDATION ---
def identify_ioc_type(ioc):
    ioc = ioc.strip()
    if re.match(r'^https?://', ioc) or re.match(r'^www\.', ioc): return "url"
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError: pass
    if re.match(r'^[a-fA-F0-9]{32}$', ioc) or re.match(r'^[a-fA-F0-9]{40}$', ioc) or re.match(r'^[a-fA-F0-9]{64}$', ioc): return "hash"
    if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', ioc): return "domain"
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
        actor_tag TEXT,
        tags TEXT
    )''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_url ON intel_reports(url)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_title ON intel_reports(title)")

    # Strict cleanup of old data
    limit_regular = (datetime.datetime.now(IL_TZ) - datetime.timedelta(days=HISTORY_DAYS)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE source NOT IN ('INCD', 'DeepWeb') AND published_at < ?", (limit_regular,))
    conn.commit()
    conn.close()

def get_existing_data():
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT url, title FROM intel_reports")
        rows = c.fetchall()
        conn.close()
        return {row[0] for row in rows}, {row[1] for row in rows}
    except Exception as e:
        log.warning("get_existing_data failed: %s", e)
        return set(), set()

# --- DEEP WEB SCANNER ---
class DeepWebScanner:
    def scan_actor(self, actor_name, limit=3):
        results = []
        try:
            query = f'"{actor_name}" cyber threat intelligence malware analysis report'
            with DDGS() as ddgs:
                ddg_results = list(ddgs.text(query, max_results=limit))
                existing_urls, _ = get_existing_data()
                for res in ddg_results:
                    url = res.get('href')
                    if url in existing_urls: continue
                    results.append({
                        "title": res.get('title'),
                        "url": url,
                        "date": datetime.datetime.now(IL_TZ).isoformat(),
                        "source": "DeepWeb",
                        "summary": res.get('body', 'No summary available.'),
                        "actor_tag": actor_name
                    })
        except Exception as e:
            log.warning("DeepWeb scan failed for %s: %s", actor_name, e)
        return results

# --- CONNECTION & AI ENGINES ---
class ConnectionManager:
    @staticmethod
    def check_groq(key):
        if not key: return False, "Missing Key"
        if key.startswith("gsk_"): return True, "Connected"
        return False, "Invalid Format"

async def query_groq_api(api_key, prompt, model="llama-3.3-70b-versatile", json_mode=True):
    if not api_key: return "Error: Missing API Key"
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    models = [model, "llama-3.1-8b-instant"]
    for m in models:
        payload = {"model": m, "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
        if json_mode: payload["response_format"] = {"type": "json_object"}
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(url, json=payload, headers=headers, timeout=45) as resp:
                    if resp.status == 429:
                        time.sleep(1)
                        continue
                    if resp.status == 200:
                        data = await resp.json()
                        return data['choices'][0]['message']['content']
            except Exception as e:
                log.warning("Groq request failed (model=%s): %s", m, e)
                continue
    return None

class AIBatchProcessor:
    def __init__(self, key):
        self.key = key

    def _determine_tag_severity(self, text, source):
        text = text.lower()
        sev, tag = "Medium", "General"
        if any(x in text for x in ['exploited', 'zero-day', 'ransomware', 'critical', 'cve-202', 'apt', 'state-sponsored']): sev = "High"
        if source == "INCD" or "israel" in text or "iran" in text: tag = "Israel"
        elif "cve-" in text or "patch" in text or "vulnerability" in text: tag = "Vulnerabilities"
        elif "phishing" in text or "credential" in text: tag = "Phishing"
        elif "malware" in text or "trojan" in text or "backdoor" in text: tag = "Malware"
        elif "research" in text or "analysis" in text: tag = "Research"
        if source == "INCD":  # national cyber directorate alerts are always high-priority
            sev = "High"
        return tag, sev

    def is_similar(self, a, b, threshold=0.75):
        return SequenceMatcher(None, a, b).ratio() > threshold

    async def analyze_batch(self, items):
        if not items: return []
        existing_urls, existing_titles = get_existing_data()

        items_to_process = [i for i in items if i['url'] not in existing_urls and not is_noise(i)]
        if not items_to_process: return []

        # Deduplication (Python Side)
        unique_items = []
        for item in items_to_process:
            if any(self.is_similar(item['title'], t) for t in existing_titles): continue
            if any(self.is_similar(item['title'], u['title']) for u in unique_items): continue
            unique_items.append(item)

        if not unique_items: return []

        chunk_size = 10
        results = []

        system_instruction = """
        You are a Cyber Intelligence Analyst.

        **MISSION:**
        1. Analyze the news items.
        2. MERGE only if they describe the EXACT same event (Same Victim + Same Attack).
        3. DO NOT discard unique items. If in doubt, keep it separate.

        **OUTPUT LANGUAGE**: Hebrew ONLY (Technical terms in English).

        **REPORT STRUCTURE (JSON):**
        {"items": [
            {
                "id": (int) ID matching input,
                "title": "Professional Hebrew Title",
                "summary": "• **תמונת מצב**: What happened.\n• **ממצאים טכניים**: CVEs, Malware.\n• **משמעויות**: Impact."
            }
        ]}
        """

        for i in range(0, len(unique_items), chunk_size):
            chunk = unique_items[i:i+chunk_size]
            chunk_results = []

            # --- AI path (only if a key is configured) ---
            if self.key:
                batch_text = "\n".join([f"ID:{idx} | Title: {x['title']} | Content: {x['summary'][:1500]}" for idx, x in enumerate(chunk)])
                prompt = f"{system_instruction}\n\nDATA:\n{batch_text}"

                res = await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=True)

                if res:
                    try:
                        data = json.loads(res)
                        for p_item in data.get("items", []):
                            idx = p_item.get('id')
                            if idx is not None and 0 <= idx < len(chunk):
                                original = chunk[idx]

                                # Groq already returns operational Hebrew; the former
                                # google-generativeai "polish" pass was end-of-life and removed.
                                final_title = p_item.get('title') or ""
                                final_summary = p_item.get('summary') or ""

                                full_text = final_title + final_summary
                                final_tag, final_sev = self._determine_tag_severity(full_text, original['source'])

                                chunk_results.append({
                                    "category": "News", "severity": final_sev,
                                    "title": final_title, "summary": final_summary,
                                    "published_at": original['date'],
                                    "source": original['source'], "url": original['url'],
                                    "actor_tag": original.get('actor_tag', None), "tags": final_tag
                                })
                    except Exception as e:
                        log.warning("failed to parse Groq JSON response: %s", e)

            # --- Graceful degradation ---
            # If the AI produced nothing for this chunk (no key, Groq error, or an
            # unparseable response), keep the RAW fetched items so the feed still
            # shows real intel instead of going blank. Tag/severity stay rule-based.
            if not chunk_results:
                if not self.key:
                    log.info("no Groq key: showing %d raw item(s) without AI summary", len(chunk))
                else:
                    log.warning("Groq returned no usable output: falling back to %d raw item(s)", len(chunk))
                for original in chunk:
                    raw_title = original.get('title') or ""
                    raw_summary = original.get('summary') or ""
                    final_tag, final_sev = self._determine_tag_severity(f"{raw_title} {raw_summary}", original['source'])
                    chunk_results.append({
                        "category": "Raw", "severity": final_sev,
                        "title": raw_title, "summary": raw_summary,
                        "published_at": original['date'],
                        "source": original['source'], "url": original['url'],
                        "actor_tag": original.get('actor_tag', None), "tags": final_tag
                    })

            results.extend(chunk_results)

        return results

    async def analyze_single_ioc(self, ioc, ioc_type, data):
        lean_data = self._extract_key_intel(data)
        prompt = f"Act as Senior SOC Analyst. Target: {ioc} ({ioc_type}). Data: {json.dumps(lean_data)}. Output Hebrew Markdown analysis."
        res = await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)
        return res if res else "Analysis unavailable."

    def _extract_key_intel(self, raw_data):
        summary = {}
        if 'virustotal' in raw_data and raw_data['virustotal']:
            vt = raw_data['virustotal']
            summary['virustotal'] = {'malicious_votes': vt.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0), 'tags': vt.get('attributes', {}).get('tags', [])}
        return summary

class ThreatLookup:
    def __init__(self, vt_key=None, urlscan_key=None, abuse_key=None):
        self.vt_key, self.urlscan_key, self.abuse_key = vt_key, urlscan_key, abuse_key
    def query_virustotal(self, ioc, ioc_type):
        if not self.vt_key: return None
        try:
            endpoint = f"urls/{base64.urlsafe_b64encode(ioc.encode()).decode().strip('=')}" if ioc_type == "url" else f"{'ip_addresses' if ioc_type == 'ip' else 'domains' if ioc_type == 'domain' else 'files'}/{ioc}"
            res = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}", headers={"x-apikey": self.vt_key}, timeout=10)
            return res.json().get('data', {}) if res.status_code == 200 else None
        except Exception as e:
            log.warning("VirusTotal query failed for %s: %s", ioc, e)
            return None
    def query_urlscan(self, ioc):
        if not self.urlscan_key: return None
        try:
            res = requests.get(f"https://urlscan.io/api/v1/search/?q=\"{ioc}\"", headers={"API-Key": self.urlscan_key}, timeout=10)
            data = res.json()
            if data.get('results'):
                return requests.get(f"https://urlscan.io/api/v1/result/{data['results'][0]['_id']}/", headers={"API-Key": self.urlscan_key}, timeout=10).json()
            return None
        except Exception as e:
            log.warning("URLScan query failed for %s: %s", ioc, e)
            return None
    def query_abuseipdb(self, ip):
        if not self.abuse_key: return None
        try:
            return requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': self.abuse_key}, params={'ipAddress': ip}, timeout=10).json().get('data', {})
        except Exception as e:
            log.warning("AbuseIPDB query failed for %s: %s", ip, e)
            return None

class AnalystToolkit:
    @staticmethod
    def get_tools():
        return {
            "Analysis": [{"name": "CyberChef", "url": "https://gchq.github.io/CyberChef/", "desc": "פענוח", "icon": "🔪"},{"name": "Any.Run", "url": "https://app.any.run/", "desc": "Sandbox", "icon": "📦"},{"name": "UnpacMe", "url": "https://www.unpac.me/", "desc": "Unpacking", "icon": "🔓"}],
            "Lookup": [{"name": "VirusTotal", "url": "https://www.virustotal.com/", "desc": "Scanner", "icon": "🦠"},{"name": "AbuseIPDB", "url": "https://www.abuseipdb.com/", "desc": "Reputation", "icon": "🚫"},{"name": "Talos", "url": "https://talosintelligence.com/", "desc": "Intel", "icon": "🛡️"}],
            "Tools": [{"name": "MxToolbox", "url": "https://mxtoolbox.com/", "desc": "Network", "icon": "🔧"},{"name": "URLScan", "url": "https://urlscan.io/", "desc": "Web Scan", "icon": "📷"},{"name": "OTX", "url": "https://otx.alienvault.com/", "desc": "Open Intel", "icon": "👽"}]
        }

class APTSheetCollector:
    def fetch_threats(self):
        return [
            {"name": "MuddyWater", "origin": "Iran (MOIS)", "target": "Israel", "type": "Espionage", "tools": "PowerShell, Ligolo", "desc": "Linked to Iran's Ministry of Intelligence (MOIS)."},
            {"name": "OilRig (APT34)", "origin": "Iran (IRGC)", "target": "Israel", "type": "Espionage", "tools": "DNSpionage", "desc": "Targets critical infrastructure."},
            {"name": "Agonizing Serpens", "origin": "Iran", "target": "Israel", "type": "Wiper", "tools": "BiBiWiper", "desc": "Data-destruction (wiper) operations."}
        ]

class CTICollector:
    SOURCES = [
        # --- General / international news ---
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "TheHackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "Malwarebytes", "url": "https://www.malwarebytes.com/blog/feed/", "type": "rss"},
        {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/", "type": "rss"},
        {"name": "Security Affairs", "url": "https://securityaffairs.com/feed", "type": "rss"},
        {"name": "GBHackers", "url": "https://gbhackers.com/feed/", "type": "rss"},
        {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "type": "rss"},
        # --- Top-tier threat research ---
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"},
        {"name": "SANS ISC", "url": "https://isc.sans.edu/rssfeed_full.xml", "type": "rss"},
        {"name": "Securelist", "url": "https://securelist.com/feed/", "type": "rss"},
        {"name": "Talos", "url": "https://blog.talosintelligence.com/rss/", "type": "rss"},
        {"name": "Check Point", "url": "https://research.checkpoint.com/feed/", "type": "rss"},
        {"name": "ESET", "url": "https://www.welivesecurity.com/en/rss/feed/", "type": "rss"},
        {"name": "Mandiant", "url": "https://www.mandiant.com/resources/blog/rss.xml", "type": "rss"},
        {"name": "Krebs", "url": "https://krebsonsecurity.com/feed/", "type": "rss"},
        {"name": "Schneier", "url": "https://www.schneier.com/feed/atom/", "type": "rss"},
        {"name": "DFIR Report", "url": "https://thedfirreport.com/feed/", "type": "rss"},
        {"name": "Project Zero", "url": "https://googleprojectzero.blogspot.com/feeds/posts/default", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        # --- Israel / Hebrew ---
        {"name": "People & Computers", "url": "https://www.pc.co.il/feed/", "type": "rss"},
        {"name": "Cyber News IL", "url": "https://rss.app/feeds/Ho4gIVhEXQwiIoOx.xml", "type": "rss"},
        {"name": "CyberSafe", "url": "https://cybersafe.co.il/category/%D7%97%D7%93%D7%A9%D7%95%D7%AA-%D7%A1%D7%99%D7%99%D7%91%D7%A8/feed/", "type": "rss"},
        {"name": "Techz", "url": "https://techz.co.il/tag/%D7%A1%D7%99%D7%99%D7%91%D7%A8/feed/", "type": "rss"},
        {"name": "INCD", "url": "https://www.gov.il/he/rss/news_list?officeId=4bcc13f5-fed6-4b8c-b8ee-7bf4a6bc81c8", "type": "rss"},
        {"name": "INCD", "url": "https://t.me/s/Israel_Cyber", "type": "telegram"},
        {"name": "INCD Alerts", "url": "https://t.me/s/CyberGovIL", "type": "telegram"},
    ]

    async def fetch_item(self, session, source):
        """Fetch one source. Returns a status dict so callers can surface failures:
        {source, url, ok, items, error}. ok=False means the source did NOT load
        (vs. ok=True with an empty list, which means "loaded, nothing recent")."""
        items = []
        try:
            async with session.get(source['url'], headers=get_headers(), timeout=30) as resp:
                if resp.status != 200:
                    log.warning("source %s returned HTTP %s", source['name'], resp.status)
                    return {"source": source['name'], "url": source['url'], "ok": False, "items": [], "error": f"HTTP {resp.status}"}
                content = await resp.text()

                if source['type'] == 'rss':
                    feed = feedparser.parse(content)
                    # --- FETCH LIMIT = 100 ---
                    for entry in feed.entries[:FETCH_LIMIT]:
                        link = getattr(entry, 'link', None)
                        if not link:
                            continue
                        date_raw = getattr(entry, 'published_parsed', None) or getattr(entry, 'updated_parsed', None)
                        pub_date = parse_flexible_date(date_raw)

                        # --- STRICT 7-DAY FILTER ---
                        if is_recent(pub_date):
                            items.append({"title": getattr(entry, 'title', '(no title)'), "url": link, "date": pub_date, "source": source['name'], "summary": _entry_summary(entry)})

                elif source['type'] == 'json':
                     data = json.loads(content)
                     # Fetch more to allow date filtering
                     for v in data.get('vulnerabilities', [])[:50]:
                         pub_date = parse_flexible_date(v.get('dateAdded'))
                         if is_recent(pub_date):
                             items.append({"title": f"KEV: {v['cveID']}", "url": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}", "date": pub_date, "source": "CISA", "summary": v.get('shortDescription')})

                elif source['type'] == 'telegram':
                    soup = BeautifulSoup(content, 'html.parser')
                    for msg in soup.find_all('div', class_='tgme_widget_message_wrap')[-50:]:
                        try:
                            time_tag = msg.find('time')
                            date_raw = time_tag['datetime'] if time_tag else None
                            pub_date = parse_flexible_date(date_raw)
                            text_div = msg.find('div', class_='tgme_widget_message_text')
                            link_tag = msg.find('a', class_='tgme_widget_message_date')
                            if not text_div or not link_tag:
                                continue
                            # INCD/Telegram alerts are kept regardless of the 7-day window
                            # (low volume, national-CERT priority) so the newest all appear.
                            _t = text_div.get_text(separator=' ').strip()
                            # A distinct per-post title; a constant title would collapse every
                            # alert into one under the title-similarity de-duplication.
                            _title = (_t[:80].rstrip() + '…') if len(_t) > 80 else (_t or "INCD Cyber Alert")
                            items.append({"title": _title, "url": link_tag['href'], "date": pub_date, "source": "INCD", "summary": _t})
                        except Exception as e:
                            log.debug("telegram message parse skipped: %s", e)
        except Exception as e:
            log.warning("source fetch failed: %s (%s): %s", source['name'], source['url'], e)
            return {"source": source['name'], "url": source['url'], "ok": False, "items": [], "error": str(e)}
        return {"source": source['name'], "url": source['url'], "ok": True, "items": items, "error": None}

    async def get_all_data(self):
        """Returns (items, statuses). `items` is the flat list of fetched reports;
        `statuses` is one entry per source so the UI can show source health."""
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_item(session, s) for s in self.SOURCES]
            results = await asyncio.gather(*tasks)
        items = [it for r in results for it in r["items"]]
        statuses = [{"source": r["source"], "url": r["url"], "ok": r["ok"], "count": len(r["items"]), "error": r["error"]} for r in results]
        return items, statuses

def save_reports(raw, analyzed):
    conn = sqlite3.connect(DB_NAME)
    c, cnt = conn.cursor(), 0
    for item in analyzed:
        try:
            c.execute("INSERT OR IGNORE INTO intel_reports (timestamp,published_at,source,url,title,category,severity,summary,actor_tag,tags) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (datetime.datetime.now(IL_TZ).isoformat(), item['published_at'], item['source'], item['url'], item['title'], item['category'], item['severity'], item['summary'], item.get('actor_tag'), item.get('tags')))
            if c.rowcount > 0: cnt += 1
        except Exception as e:
            log.warning("failed to save report %s: %s", item.get('url'), e)
    conn.commit()
    conn.close()
    return cnt
