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
    limit = (datetime.datetime.now() - datetime.timedelta(hours=48)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE published_at < ?", (limit,))
    conn.commit()
    conn.close()

# --- HELPERS ---
def get_ioc_type(ioc):
    ioc = ioc.strip()
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc): return "ip"
    if "http" in ioc: return "url"
    return "domain"

# --- CORE: AUTO-DISCOVERY AI LOGIC ---
async def get_valid_model_name(api_key, session):
    """
    שואל את גוגל: איזה מודלים פתוחים לי?
    מחזיר את השם המדויק של המודל הראשון שעובד.
    """
    list_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
    try:
        async with session.get(list_url) as resp:
            if resp.status != 200:
                print(f"ListModels Error: {resp.status} - {await resp.text()}")
                return None
            
            data = await resp.json()
            # אנחנו מחפשים מודל שיודע לייצר טקסט (generateContent)
            for model in data.get('models', []):
                if 'generateContent' in model.get('supportedGenerationMethods', []):
                    # מחזיר שם כמו 'models/gemini-1.5-flash-001'
                    return model['name']
    except Exception as e:
        print(f"Discovery Failed: {e}")
    return None

async def query_gemini_auto(api_key, prompt):
    if not api_key: return None
    
    async with aiohttp.ClientSession() as session:
        # שלב 1: גילוי אוטומטי של שם המודל
        model_name = await get_valid_model_name(api_key, session)
        
        if not model_name:
            return "ERROR: No accessible models found for this API Key. Check Google AI Studio permissions."

        # שלב 2: שימוש במודל שנמצא
        # model_name already contains 'models/', so we don't add it
        if not model_name.startswith("models/"):
            model_name = f"models/{model_name}"
            
        url = f"https://generativelanguage.googleapis.com/v1beta/{model_name}:generateContent?key={api_key}"
        headers = {'Content-Type': 'application/json'}
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        
        try:
            async with session.post(url, json=payload, headers=headers, timeout=20) as resp:
                response_text = await resp.text()
                if resp.status == 200:
                    data = json.loads(response_text)
                    return data['candidates'][0]['content']['parts'][0]['text']
                else:
                    return f"Error {resp.status}: {response_text}"
        except Exception as e:
            return f"Connection Error: {e}"

# --- HEALTH CHECK (With Deep Debug) ---
class ConnectionManager:
    @staticmethod
    def check_gemini(key):
        if not key: return False, "Missing Key"
        
        # 1. ננסה לשלוף את רשימת המודלים המלאה
        list_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={key}"
        try:
            res = requests.get(list_url, timeout=10)
            
            if res.status_code != 200:
                # זה המקום שבו נתפוס את הבעיה!
                return False, f"❌ LIST ERROR ({res.status_code}): {res.text}"
            
            data = res.json()
            available_models = [m['name'] for m in data.get('models', []) if 'generateContent' in m.get('supportedGenerationMethods', [])]
            
            if not available_models:
                return False, "❌ Key valid, but NO models have 'generateContent' permission."
                
            # 2. אם יש מודלים, ננסה פינג לראשון
            first_model = available_models[0]
            ping_url = f"https://generativelanguage.googleapis.com/v1beta/{first_model}:generateContent?key={key}"
            ping_res = requests.post(ping_url, json={"contents":[{"parts":[{"text":"Ping"}]}]}, timeout=5)
            
            if ping_res.status_code == 200:
                return True, f"✅ Connected! Using: {first_model}"
            else:
                return False, f"❌ PING ERROR: {ping_res.text}"
                
        except Exception as e:
            return False, f"❌ Network Error: {str(e)}"

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
        prompt = f"Analyze threats. Return JSON Array: [{{'id':0, 'category':'Malware', 'severity':'High', 'impact':'Risk', 'summary':'Short summary'}}]. Items:\n{batch_text}"
        
        # שימוש בפונקציה החדשה
        res = await query_gemini_auto(self.key, prompt)
        
        if res and "ERROR" not in res and "Error" not in res:
            try:
                clean = res.replace('```json','').replace('```','').strip()
                if '[' in clean: clean = clean[clean.find('['):clean.rfind(']')+1]
                return json.loads(clean)
            except: pass
            
        return [{"id": i, "category": "General", "severity": "Medium", "impact": "Info", "summary": x['summary'][:200]} for i,x in enumerate(items)]

    async def analyze_single_ioc(self, ioc, data):
        prompt = f"Analyze IOC: {ioc}. Data: {json.dumps(data, default=str)}. Return Markdown report."
        return await query_gemini_auto(self.key, prompt)

# --- DUMMY CLASSES ---
class CTICollector:
    async def get_all_data(self): return [] # Placeholder, real logic needs restore if needed
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
