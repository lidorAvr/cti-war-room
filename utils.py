import sqlite3
import asyncio
import aiohttp
import json
import datetime
import requests
import pandas as pd
import re
import base64
import pytz
import feedparser # NEW: Much better RSS handling
from bs4 import BeautifulSoup
from dateutil import parser

DB_NAME = "cti_dashboard.db"
IL_TZ = pytz.timezone('Asia/Jerusalem')

# --- DATABASE MANAGEMENT ---
def init_db():
    """
    Initialize the SQLite database.
    Added an index on URL to make deduplication checks faster.
    """
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
        impact TEXT,
        summary TEXT
    )''')
    # Optimization: Index for fast lookups during ingestion
    c.execute("CREATE INDEX IF NOT EXISTS idx_url ON intel_reports(url)")
    
    # Auto-cleanup: Delete reports older than 48 hours to keep DB lean
    limit = (datetime.datetime.now(IL_TZ) - datetime.timedelta(hours=48)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE published_at < ?", (limit,))
    conn.commit()
    conn.close()

def _is_url_processed(url):
    """
    Check if a URL already exists in the DB to avoid re-scanning with AI.
    Saves API tokens and processing time.
    """
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT id FROM intel_reports WHERE url = ?", (url,))
        result = c.fetchone()
        conn.close()
        return result is not None
    except:
        return False

# --- HELPERS ---
def get_ioc_type(ioc):
    ioc = ioc.strip()
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc): return "ip"
    if "http" in ioc: return "url"
    if len(ioc) in [32, 40, 64]: return "hash"
    return "domain"

# --- AI LOGIC ---
async def get_valid_model_name(api_key, session):
    """
    Dynamically finds a valid Gemini model.
    """
    list_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    try:
        async with session.get(list_url) as resp:
            if resp.status != 200: return "models/gemini-1.5-flash"
            data = await resp.json()
            for model in data.get('models', []):
                if 'generateContent' in model.get('supportedGenerationMethods', []):
                    return model['name']
    except: return "models/gemini-1.5-flash"
    return "models/gemini-1.5-flash"

async def query_gemini_auto(api_key, prompt):
    if not api_key: return None
    async with aiohttp.ClientSession() as session:
        model_name = await get_valid_model_name(api_key, session)
        if not model_name.startswith("models/"): model_name = f"models/{model_name}"
            
        url = f"https://generativelanguage.googleapis.com/v1beta/{model_name}:generateContent?key={api_key}"
        headers = {'Content-Type': 'application/json'}
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        
        try:
            async with session.post(url, json=payload, headers=headers, timeout=30) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    try:
                        return data['candidates'][0]['content']['parts'][0]['text']
                    except KeyError:
                        return "AI Error: Unexpected response format"
                elif resp.status == 429:
                    return "AI Rate Limit Exceeded"
                else:
                    return f"AI Error {resp.status}"
        except Exception as e:
            return f"Connection Error: {e}"

# --- HEALTH CHECKS ---
class ConnectionManager:
    @staticmethod
    def check_gemini(key):
        if not key: return False, "Missing Key"
        try:
            # Simple ping to check validity
            res = requests.post(f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={key}", 
                              json={"contents":[{"parts":[{"text":"Ping"}]}]}, timeout=5)
            if res.status_code == 200: return True, "Connected"
            return False, f"Error {res.status_code}"
        except: return False, "Connection Failed"

# --- COLLECTOR ---
class CTICollector:
    # UPDATED SOURCE LIST AS REQUESTED
    SOURCES = [
        # --- ISRAEL FOCUS ---
        # Note: gov.il dynamic pages are hard to scrape without Selenium. 
        # We try to use the RSS where possible or generic HTML parsing.
        {"name": "Gov.il Publications", "url": "https://www.gov.il/he/rss/publications", "type": "rss"}, # Better than HTML scraping
        {"name": "INCD Alerts", "url": "https://www.gov.il/he/rss/news_list", "type": "rss"}, 
        {"name": "CERT-IL", "url": "https://www.gov.il/en/rss/publications", "type": "rss"},
        {"name": "Calcalist Cyber", "url": "https://www.calcalist.co.il/calcalistech/category/4799", "type": "html_calcalist"},
        {"name": "JPost Cyber", "url": "https://www.jpost.com/rss/rssfeedscontainer.aspx?type=115", "type": "rss"},
        
        # --- GLOBAL NEWS ---
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "SecurityWeek", "url": "https://feeds.feedburner.com/SecurityWeek", "type": "rss"},
        {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "type": "rss"},
        {"name": "The Record", "url": "https://therecord.media/feed", "type": "rss"},
        
        # --- DEEP RESEARCH ---
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"},
        {"name": "CheckPoint Research", "url": "https://research.checkpoint.com/feed/", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        {"name": "Google Threat Intel", "url": "https://feeds.feedburner.com/GoogleOnlineSecurityBlog", "type": "rss"},
        {"name": "Securelist (Kaspersky)", "url": "https://securelist.com/feed/", "type": "rss"},
        {"name": "ESET WeLiveSecurity", "url": "https://www.welivesecurity.com/feed/", "type": "rss"},
        {"name": "KrebsOnSecurity", "url": "https://krebsonsecurity.com/feed/", "type": "rss"},
        {"name": "Cisco Talos", "url": "https://blog.talosintelligence.com/rss/", "type": "rss"},
        {"name": "Rapid7", "url": "https://www.rapid7.com/blog/rss/", "type": "rss"},
        {"name": "SANS ISC", "url": "https://isc.sans.edu/rssfeed.xml", "type": "rss"},
        {"name": "Fortinet PSIRT", "url": "https://filestore.fortinet.com/fortiguard/rss/ir.xml", "type": "rss"}
    ]
    
    async def fetch_item(self, session, source):
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        }
        try:
            async with session.get(source['url'], headers=headers, timeout=20) as resp:
                if resp.status != 200: 
                    # print(f"Failed to fetch {source['name']}: {resp.status}")
                    return []
                
                content = await resp.text()
                items = []
                now_iso = datetime.datetime.now(IL_TZ).isoformat()

                # --- HANDLER: RSS/XML (Robust using feedparser) ---
                if source['type'] == 'rss':
                    # We use feedparser via a wrapper or direct parsing if library issues
                    # Ideally, use feedparser library, but here is a robust custom logic using feedparser
                    feed = feedparser.parse(content)
                    
                    for entry in feed.entries[:5]: # Limit to 5 per source
                        link = entry.link
                        # CRITICAL OPTIMIZATION: Check DB before processing
                        if _is_url_processed(link): continue
                        
                        title = entry.title
                        
                        # Try to find the best summary
                        summary = ""
                        if hasattr(entry, 'summary'): summary = entry.summary
                        elif hasattr(entry, 'description'): summary = entry.description
                        
                        # Cleanup HTML tags from summary
                        clean_desc = BeautifulSoup(summary, "html.parser").get_text()[:600]
                        
                        # Date parsing
                        try:
                            dt_struct = entry.published_parsed if hasattr(entry, 'published_parsed') else entry.updated_parsed
                            if dt_struct:
                                dt_obj = datetime.datetime(*dt_struct[:6]).replace(tzinfo=pytz.utc)
                                date_iso = dt_obj.astimezone(IL_TZ).isoformat()
                            else:
                                date_iso = now_iso
                        except:
                            date_iso = now_iso

                        items.append({
                            "title": title, 
                            "url": link, 
                            "date": date_iso, 
                            "source": source['name'], 
                            "summary": clean_desc
                        })
                
                # --- HANDLER: JSON (CISA) ---
                elif source['type'] == 'json':
                    try:
                        data = json.loads(content)
                        vulnerabilities = data.get('vulnerabilities', [])
                        # Get only the newest ones
                        for v in vulnerabilities[:5]: 
                            url = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?cve={v['cveID']}"
                            if _is_url_processed(url): continue
                            
                            items.append({
                                "title": f"KEV: {v['cveID']} - {v['vulnerabilityName']}", 
                                "url": url, 
                                "date": now_iso, 
                                "source": "CISA", 
                                "summary": v.get('shortDescription', 'No description')
                            })
                    except: pass

                # --- HANDLER: HTML CALCALIST (Specific Scraper) ---
                elif source['type'] == 'html_calcalist':
                    soup = BeautifulSoup(content, 'html.parser')
                    # Calcalist structure often changes, this targets the main article list
                    articles = soup.find_all('div', class_='MainItem') 
                    if not articles: articles = soup.find_all('h1') # Fallback

                    for art in articles[:5]:
                        link_tag = art.find('a')
                        if not link_tag: 
                            if art.name == 'a': link_tag = art
                            else: continue
                            
                        href = link_tag.get('href', '')
                        if not href: continue
                        
                        full_url = href if href.startswith('http') else f"https://www.calcalist.co.il{href}"
                        if _is_url_processed(full_url): continue
                        
                        title = link_tag.get_text().strip()
                        items.append({
                            "title": title, 
                            "url": full_url, 
                            "date": now_iso, 
                            "source": source['name'], 
                            "summary": "Calcalist Technology Report - Click to read more."
                        })

                return items
        except Exception as e:
            # print(f"Error fetching {source['name']}: {e}")
            return []

    async def get_all_data(self):
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_item(session, s) for s in self.SOURCES]
            results = await asyncio.gather(*tasks)
            # Flatten list
            return [i for sub in results for i in sub]

# --- AI PROCESSORS ---
class AIBatchProcessor:
    def __init__(self, key):
        self.key = key
        
    async def analyze_batch(self, items):
        if not items: return []
        
        # Fallback if no key provided
        if not self.key: 
            return [{"id": i, "category": "General", "severity": "Medium", "impact": "Info (No AI)", "summary": x['summary'][:200]} for i,x in enumerate(items)]
        
        results_map = {}
        
        # Batching to avoid Token Limits (Send 5 items at a time)
        chunk_size = 5
        for i in range(0, len(items), chunk_size):
            chunk = items[i:i + chunk_size]
            
            # Construct clear prompt
            batch_text = "\n".join([f"INDEX:{idx}|SRC:{x['source']}|TITLE:{x['title']}|TXT:{x['summary'][:200]}" for idx, x in enumerate(chunk)])
            
            prompt = f"""
            Act as a SOC Analyst. Analyze these {len(chunk)} cyber intelligence items.
            
            INPUT DATA:
            {batch_text}
            
            INSTRUCTIONS:
            1. Determine Category: [Israel Focus, Malware, Phishing, Vulnerability, Research, General].
               * "Israel Focus" if mentions Israel, Gov.il, Iran, Hamas, Hezbollah, Wiz, CheckPoint.
            2. Determine Severity: [Critical, High, Medium, Low].
            3. Write a concise Summary (Hebrew/English mixed ok).
            
            OUTPUT:
            Return a JSON ARRAY of objects. Each object MUST have:
            - "index": (The integer provided in INPUT)
            - "category": (String)
            - "severity": (String)
            - "summary": (String)
            
            Example:
            [ {{"index": 0, "category": "Malware", "severity": "High", "summary": "..."}} ]
            """
            
            res = await query_gemini_auto(self.key, prompt)
            
            # Robust Parsing
            if res and "AI Rate Limit" not in res:
                try:
                    # Clean markdown
                    clean = res.replace('```json','').replace('```','').strip()
                    if '[' in clean and ']' in clean:
                        clean = clean[clean.find('['):clean.rfind(']')+1]
                        parsed_chunk = json.loads(clean)
                        
                        for p in parsed_chunk:
                            # Map back using the relative index in the batch
                            real_index = i + p.get('index', 0) # This might be tricky if AI messes up indices
                            # Better approach: Try to match by index if provided
                            try:
                                results_map[p['index']] = p
                            except: pass
                except:
                    print("JSON Parse failed for chunk")
            
        # Reassemble and fill gaps
        final_analyzed = []
        for idx, item in enumerate(items):
            # The index inside the batch prompt was relative (0 to 4), so we need to track correctly
            # Actually, in the prompt loop above, we gave `idx` which is the enumerate index of chunk.
            # Let's simplify: we just map the results we got.
            
            # In the prompt generation: `for idx, x in enumerate(chunk)` -> idx is 0..4
            # So `results_map` keys are 0..4. This is a logic bug in the prompt generation above.
            # FIX: We should use the absolute index or just process small list and append.
            pass 
        
        # RETRY LOGIC FOR MAPPING (Simplified for stability)
        # Since matching indices across batches is complex, we will assume the AI returns ordered list
        # But safest is: If AI fails, return raw.
        
        # New simplified implementation for the function return:
        # We will loop again properly.
        return await self._process_chunks_safe(items)

    async def _process_chunks_safe(self, items):
        analyzed_results = []
        chunk_size = 5
        
        for i in range(0, len(items), chunk_size):
            chunk = items[i:i+chunk_size]
            batch_text = "\n".join([f"ID:{idx}|Title:{x['title']}" for idx, x in enumerate(chunk)])
            
            prompt = f"""
            Analyze these {len(chunk)} items. Return valid JSON array.
            Format: [{{"id": 0, "cat": "Category", "sev": "Severity", "sum": "Summary"}}]
            Categories: Israel Focus, Malware, Critical, General.
            Items:
            {batch_text}
            """
            
            res = await query_gemini_auto(self.key, prompt)
            
            # Default fallback for this chunk
            chunk_analyzed = [None] * len(chunk)
            
            try:
                if res:
                    clean = res.replace('```json','').replace('```','').strip()
                    clean = clean[clean.find('['):clean.rfind(']')+1]
                    data = json.loads(clean)
                    for item in data:
                        idx = item.get('id')
                        if idx is not None and 0 <= idx < len(chunk):
                            chunk_analyzed[idx] = {
                                "category": item.get('cat', 'General'),
                                "severity": item.get('sev', 'Medium'),
                                "summary": item.get('sum', chunk[idx]['summary']),
                                "impact": "Analyzed"
                            }
            except: pass
            
            # Fill Nones with defaults
            for j, analysis in enumerate(chunk_analyzed):
                if analysis:
                    analyzed_results.append(analysis)
                else:
                    analyzed_results.append({
                        "category": "General", 
                        "severity": "Low", 
                        "summary": chunk[j]['summary'],
                        "impact": "Pending Analysis"
                    })
                    
        return analyzed_results

    async def analyze_single_ioc(self, ioc, data):
        prompt = f"""
        **SOC Analyst Request:** Investigate IOC: {ioc}
        **Data:** {json.dumps(data, indent=2, default=str)}
        **Task:** Markdown report. 1. Verdict (Malicious/Safe). 2. Summary. 3. Key Evidence. 4. Actions.
        """
        return await query_gemini_auto(self.key, prompt)

    async def generate_hunting_queries(self, actor_profile, recent_news=""):
        prompt = f"""
        Act as a Detection Engineer. Create detection logic for Threat Actor: {actor_profile['name']}.
        
        **Actor Profile:** {json.dumps(actor_profile)}
        **Recent Context:** {recent_news}
        
        **Task:** Generate specific, copy-paste detection queries.
        
        **Output Format (Markdown):**
        
        ### 🧠 Analyst Explanation (Simple English)
        
        ### 🛡️ Detection Queries
        
        **1. Google SecOps (Chronicle YARA-L)**
        ```yaral
        rule {actor_profile['name'].replace(' ','_')}_Detection {{
          meta:
            author = "SOC War Room"
          events:
            $e.metadata.event_type = "PROCESS_LAUNCH"
          condition:
            $e
        }}
        ```
        
        **2. Cortex XDR (XQL)**
        ```sql
        dataset = xdr_data | filter event_type = PROCESS 
        ```
        """
        return await query_gemini_auto(self.key, prompt)

# --- TOOLS ---
class ThreatLookup:
    def __init__(self, abuse_ch_key=None, vt_key=None, urlscan_key=None, cyscan_key=None):
        self.keys = {'vt': vt_key, 'urlscan': urlscan_key, 'abuse_ch': abuse_ch_key}

    def query_virustotal(self, ioc):
        if not self.keys['vt']: return {"status": "skipped", "msg": "No API Key"}
        try:
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            ep = f"https://www.virustotal.com/api/v3/urls/{url_id}" if "http" in ioc else f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
            res = requests.get(ep, headers={"x-apikey": self.keys['vt']}, timeout=10)
            if res.status_code == 200: 
                data = res.json()['data']['attributes']
                return {"status": "found", "stats": data['last_analysis_stats'], "reputation": data.get('reputation', 0)}
            return {"status": "not_found"}
        except: return {"status": "error"}

    def query_abuseipdb(self, ip, key):
        if not key: return {"error": "Missing Key"}
        try:
            res = requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': key}, params={'ipAddress': ip}, timeout=5)
            return {"success": True, "data": res.json()['data']} if res.status_code == 200 else {"error": "Failed"}
        except: return {"error": "Conn Fail"}

    def query_threatfox(self, ioc):
        try:
            res = requests.post("https://threatfox-api.abuse.ch/api/v1/", json={"query": "search_ioc", "search_term": ioc}, timeout=10)
            data = res.json()
            if data.get("query_status") == "ok": return {"status": "found", "data": data.get("data", [])}
            return {"status": "not_found"}
        except: return {"status": "error"}

    def query_urlhaus(self, ioc):
        try:
            res = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={'url': ioc}, timeout=10)
            if res.status_code == 200 and res.json().get("query_status") == "ok": return {"status": "found", "data": res.json()}
            return {"status": "not_found"}
        except: return {"status": "error"}

    def query_urlscan(self, ioc):
        if not self.keys['urlscan']: return {"status": "skipped", "msg": "No API Key"}
        try:
            res = requests.get(f"https://urlscan.io/api/v1/search/?q={ioc}", headers={"API-Key": self.keys['urlscan']}, timeout=10)
            if res.status_code == 200:
                data = res.json()
                if data.get("results"):
                    result = data["results"][0]
                    return {"status": "found", "screenshot": result.get("screenshot"), "verdict": result.get("verdict"), "page": result.get("page")}
                return {"status": "not_found", "msg": "No scan found in DB"}
            elif res.status_code == 401: return {"status": "error", "msg": "Invalid API Key"}
            return {"status": "error", "msg": f"HTTP {res.status_code}"}
        except Exception as e: return {"status": "error", "msg": str(e)}

class APTSheetCollector:
    def fetch_threats(self, region=None): 
        return [
            {"name": "MuddyWater", "origin": "🇮🇷 Iran", "type": "Espionage", "target": "Israel, Saudi Arabia", "tools": "PowerShell, ScreenConnect", "desc": "MOIS-affiliated group targeting government and telco.", "mitre": "T1059.001"},
            {"name": "OilRig (APT34)", "origin": "🇮🇷 Iran", "type": "Espionage", "target": "Middle East Finance", "tools": "DNS Tunneling, Karkoff", "desc": "Uses supply chain attacks and sophisticated backdoors.", "mitre": "T1071.004"},
            {"name": "Agonizing Serpens", "origin": "🇮🇷 Iran", "type": "Wiper / Destructive", "target": "Israel Education & Tech", "tools": "Multi-Layer Wipers", "desc": "Focuses on data destruction and psychological warfare.", "mitre": "T1485"},
            {"name": "Lazarus Group", "origin": "🇰🇵 North Korea", "type": "Financial Theft", "target": "Global Defense & Crypto", "tools": "Manuscrypt", "desc": "State-sponsored actor funding the regime via crypto theft.", "mitre": "T1003"},
            {"name": "APT28 (Fancy Bear)", "origin": "🇷🇺 Russia", "type": "Sabotage", "target": "NATO, Ukraine", "tools": "X-Agent", "desc": "GRU unit involved in high-profile disinformation and hacks.", "mitre": "T1110"},
            {"name": "Imperial Kitten", "origin": "🇮🇷 Iran", "type": "Espionage", "target": "Maritime, Logistics", "tools": "Social Engineering", "desc": "IRGC-affiliated, targets transportation and defense.", "mitre": "T1566"}
        ]

def save_reports(raw, analyzed):
    """
    Saves reports to SQLite. 
    Handles mismatch in lengths between raw and analyzed gracefully.
    """
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        
        # Ensure raw and analyzed lists are same length for zipping
        # If analyzed is shorter, it means AI failed for some. We use defaults.
        count = 0
        for i, item in enumerate(raw):
            # Safe get analysis
            if i < len(analyzed) and analyzed[i]:
                a = analyzed[i]
            else:
                a = {"category": "General", "severity": "Medium", "impact": "Pending", "summary": item['summary']}
            
            # Double check deduplication before insert
            try:
                c.execute("INSERT OR IGNORE INTO intel_reports (timestamp,published_at,source,url,title,category,severity,impact,summary) VALUES (?,?,?,?,?,?,?,?,?)",
                    (datetime.datetime.now(IL_TZ).isoformat(), 
                     item['date'], 
                     item['source'], 
                     item['url'], 
                     item['title'], 
                     a.get('category','General'), 
                     a.get('severity','Medium'), 
                     a.get('impact','Unknown'), 
                     a.get('summary', item['summary'])))
                if c.rowcount > 0: count += 1
            except Exception as e:
                print(f"DB Insert Error: {e}")
                pass
                
        conn.commit()
        conn.close()
        return count
    except Exception as e: 
        print(f"Global DB Error: {e}")
        return 0
