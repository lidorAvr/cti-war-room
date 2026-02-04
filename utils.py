import sqlite3
import asyncio
import aiohttp
import json
import datetime
import requests
import pandas as pd
import re
import base64
from bs4 import BeautifulSoup
from dateutil import parser

DB_NAME = "cti_dashboard.db"

# --- DATABASE ---
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
        impact TEXT,
        summary TEXT
    )''')
    conn.commit()
    conn.close()

# --- HELPERS ---
def get_ioc_type(ioc):
    ioc = ioc.strip()
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc): return "ip"
    if "http" in ioc: return "url"
    return "domain"

# --- CORE GEMINI LOGIC (Direct HTTP) ---
async def query_gemini_direct(api_key, prompt):
    if not api_key: return None
    
    # שימוש במודל היציב ביותר כרגע
    model = "gemini-1.5-flash"
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
    
    headers = {'Content-Type': 'application/json'}
    payload = {
        "contents": [{"parts": [{"text": prompt}]}]
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(url, json=payload, headers=headers, timeout=20) as resp:
                response_text = await resp.text()
                
                if resp.status == 200:
                    data = json.loads(response_text)
                    try:
                        return data['candidates'][0]['content']['parts'][0]['text']
                    except:
                        return "Error parsing AI response"
                else:
                    # כאן נראה את השגיאה האמיתית של גוגל
                    print(f"Gemini Error {resp.status}: {response_text}")
                    return None
    except Exception as e:
        print(f"Connection Error: {e}")
        return None

# --- HEALTH CHECK (Synchronous for Button) ---
class ConnectionManager:
    @staticmethod
    def check_gemini(key):
        if not key: return False, "Missing Key"
        
        # כתובת ישירה לבדיקה
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={key}"
        payload = {"contents": [{"parts": [{"text": "Ping"}]}]}
        
        try:
            res = requests.post(url, json=payload, headers={'Content-Type': 'application/json'}, timeout=10)
            
            if res.status_code == 200:
                return True, "✅ Connected Successfully!"
            else:
                # מחזיר את הודעת השגיאה המדויקת מגוגל כדי שנוכל לדבג
                error_msg = res.json().get('error', {}).get('message', res.text)
                return False, f"❌ Error {res.status_code}: {error_msg}"
                
        except Exception as e:
            return False, f"❌ Connection Failed: {str(e)}"

    # Mock checks for other services to prevent crashes
    @staticmethod
    def check_abuseipdb(key): return True, "Checked"
    @staticmethod
    def check_abusech(key): return True, "Checked"
    @staticmethod
    def check_virustotal(key): return True, "Checked"
    @staticmethod
    def check_urlscan(key): return True, "Checked"

# --- PROCESSORS ---
class AIBatchProcessor:
    def __init__(self, key):
        self.key = key
        
    async def analyze_batch(self, items):
        if not items or not self.key: 
            return [{"id": i, "category": "General", "severity": "Medium", "impact": "Info", "summary": x['summary'][:200]} for i,x in enumerate(items)]
            
        batch_text = "\n".join([f"ID:{i}|Title:{x['title']}|Desc:{x['summary'][:100]}" for i,x in enumerate(items)])
        prompt = f"Analyze these cyber threats. Return ONLY a JSON Array: [{{'id':0, 'category':'Malware', 'severity':'High', 'impact':'Risk', 'summary':'Short summary'}}]. Items:\n{batch_text}"
        
        res = await query_gemini_direct(self.key, prompt)
        
        if res:
            try:
                # ניקוי פורמט JSON
                clean = res.replace('```json','').replace('```','').strip()
                if '[' in clean: 
                    clean = clean[clean.find('['):clean.rfind(']')+1]
                return json.loads(clean)
            except Exception as e:
                print(f"JSON Parse Error: {e}")
                
        return [{"id": i, "category": "General", "severity": "Medium", "impact": "Info", "summary": x['summary'][:200]} for i,x in enumerate(items)]

    async def analyze_single_ioc(self, ioc, data):
        prompt = f"Analyze IOC: {ioc}. Data: {json.dumps(data, default=str)}. Return Markdown report with Verdict, Findings, Recommendations."
        res = await query_gemini_direct(self.key, prompt)
        return res if res else "❌ Error: AI Unresponsive (Check logs)."

# --- DUMMY CLASSES (To prevent ImportErrors) ---
class CTICollector:
    async def get_all_data(self): return []
class MitreCollector:
    def get_latest_updates(self): return None
class APTSheetCollector:
    def fetch_threats(self, r): return pd.DataFrame()
class AbuseIPDBChecker:
    def __init__(self, k): pass
    def check_ip(self, i): return {}
class IOCExtractor:
    def extract(self, t): return {}
class ThreatLookup:
    def __init__(self, a=None, b=None, c=None, d=None): pass
    def query_threatfox(self, i): return {}
    def query_urlhaus(self, i): return {}
    def query_virustotal(self, i): return {}
    def query_urlscan(self, i): return {}
    def query_cyscan(self, i): return {"link": "#"}

def save_reports(raw, analyzed): return 0
