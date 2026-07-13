"""Bilingual tagging + tag-filter regression (owner-reported).

Symptoms: selecting the Israel tag showed ZERO items, and most cards carried no
meaningful tag. Live DB proof: 53/53 rows tagged 'General'. Root causes:
English-only keywords (half the feed is Hebrew), AI items classified from their
HEBREW model output instead of the raw source text, a too-narrow keyword list,
and the newest-first cap deferring the (older-dated) INCD telegram alerts.
"""
import asyncio
import datetime
import json
import os
import re
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(REPO, "app.py")
SECRET_KEYS = ("groq_key", "vt_key", "urlscan_key", "abuseipdb_key", "gemini_key")
NOW = datetime.datetime.now(datetime.timezone.utc).isoformat()
PROC = utils.AIBatchProcessor("")


class TestBilingualTagging:
    def test_hebrew_ransomware_is_malware_high(self):
        tag, sev = PROC._determine_tag_severity("מתקפת כופרה על בית חולים", "Cyber News IL")
        assert (tag, sev) == ("Malware", "High")

    def test_hebrew_phishing_tagged(self):
        tag, _ = PROC._determine_tag_severity("קמפיין פישינג חדש בוואטסאפ", "Cyber News IL")
        assert tag == "Phishing"

    def test_hebrew_israel_tagged(self):
        tag, _ = PROC._determine_tag_severity("מתקפה על ארגון בישראל", "BleepingComputer")
        assert tag == "Israel"

    def test_hebrew_vulnerability_tagged(self):
        tag, _ = PROC._determine_tag_severity("חולשה קריטית במוצר", "Techz")
        assert tag == "Vulnerabilities"

    def test_english_flaw_and_stealer_now_match(self):
        assert PROC._determine_tag_severity("New flaw in router firmware", "X")[0] == "Vulnerabilities"
        assert PROC._determine_tag_severity("New stealer spreads via ads", "X")[0] == "Malware"

    def test_incd_alerts_source_is_israel_high(self):
        # 'INCD Alerts' previously missed the INCD special-casing (== "INCD")
        tag, sev = PROC._determine_tag_severity("הודעה כללית", "INCD Alerts")
        assert (tag, sev) == ("Israel", "High")


class TestAiItemsTaggedFromRawText:
    def test_ai_hebrew_output_does_not_hide_english_keywords(self, monkeypatch, tmp_path):
        """The raw source says 'ransomware' (→ Malware/High); the AI summary is
        Hebrew without tag keywords. Classification must use the RAW text."""
        monkeypatch.chdir(tmp_path)
        utils.init_db()

        async def _fake(key, prompt, **kw):
            ids = [int(m) for m in re.findall(r"ID:(\d+)", prompt)]
            return json.dumps({"items": [
                {"id": i, "title": "כותרת בעברית", "summary": "• **תמונת מצב**: אירוע אבטחה בארגון גדול."}
                for i in ids]})

        monkeypatch.setattr(utils, "query_groq_api", _fake)
        items = [{"title": "Ransomware gang hits logistics firm", "url": "https://t/1",
                  "date": NOW, "source": "BleepingComputer",
                  "summary": "A ransomware attack encrypted servers; the gang demands payment."}]
        out = asyncio.run(utils.AIBatchProcessor("k").analyze_batch(items))
        assert out[0]["category"] == "News"
        assert out[0]["tags"] == "Malware", f"tagged from AI text instead of raw: {out[0]['tags']}"
        assert out[0]["severity"] == "High"


class TestRetagSelfHeal:
    def test_existing_general_rows_get_retagged(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        utils.init_db()
        conn = sqlite3.connect(utils.DB_NAME)
        rows = [
            ("t", NOW, "Cyber News IL", "https://h/1", "מתקפת כופרה על ארגון ישראלי",
             "Raw", "Medium", "פרטי מתקפת הכופרה", None, "General"),
            ("t", NOW, "SecurityWeek", "https://h/2", "New flaw exploited in the wild",
             "Raw", "Medium", "actively exploited flaw", None, "General"),
        ]
        for r in rows:
            conn.execute("INSERT INTO intel_reports (timestamp,published_at,source,url,title,"
                         "category,severity,summary,actor_tag,tags) VALUES (?,?,?,?,?,?,?,?,?,?)", r)
        conn.commit(); conn.close()
        utils.retag_reports()
        got = dict(sqlite3.connect(utils.DB_NAME).execute(
            "SELECT url, tags || '|' || severity FROM intel_reports").fetchall())
        assert got["https://h/1"] == "Israel|High"          # ישראלי + כופרה
        assert got["https://h/2"] == "Vulnerabilities|High"  # flaw + exploited


class TestIncdPriorityInCap:
    def test_old_incd_items_survive_the_per_run_cap(self, monkeypatch, tmp_path):
        """INCD telegram dates are old; the newest-first cap must not defer them
        (that emptied the Israel filter after a fresh boot)."""
        old = (datetime.datetime.now(datetime.timezone.utc)
               - datetime.timedelta(days=2)).isoformat()
        items = [{"title": f"alpha{i} bravo{i} charlie{i}", "url": f"https://c/{i}", "date": NOW,
                  "source": "BleepingComputer", "summary": f"alpha{i} incident details"}
                 for i in range(45)]
        items.append({"title": "INCD urgent national alert", "url": "https://c/incd", "date": old,
                      "source": "INCD", "summary": "התרעה דחופה לציבור"})

        async def _net(*a, **k):
            return items, [{"source": "BleepingComputer", "ok": True, "count": len(items)}]

        monkeypatch.setattr(utils.CTICollector, "get_all_data", _net)
        monkeypatch.chdir(tmp_path)
        from streamlit.testing.v1 import AppTest
        # generous timeout: this is the heaviest AppTest (46-item ingest) and can
        # crawl when the whole suite runs several Streamlit runtimes in sequence
        at = AppTest.from_file(APP, default_timeout=240)
        for k in SECRET_KEYS:
            at.secrets[k] = ""
        at.run()
        assert len(at.exception) == 0, [e.value for e in at.exception]
        conn = sqlite3.connect(utils.DB_NAME)
        rows = conn.execute(
            "SELECT source, tags, severity FROM intel_reports WHERE url='https://c/incd'").fetchall()
        saved = conn.execute("SELECT COUNT(*), GROUP_CONCAT(DISTINCT source) FROM intel_reports").fetchone()
        conn.close()
        assert rows, f"old-dated INCD item was deferred by the cap (saved: {saved})"
        assert rows[0][1] == "Israel" and rows[0][2] == "High"


class TestIsraelFilterUI:
    def test_israel_filter_shows_israel_items(self, monkeypatch, tmp_path):
        """End-to-end regression for the owner's exact click: select the Israel
        tag → Israel-tagged cards must render (including a legacy-Hebrew row)."""
        import utils as u

        async def _no_network(*a, **k):
            return [], []

        monkeypatch.setattr(u.CTICollector, "get_all_data", _no_network)
        monkeypatch.chdir(tmp_path)
        u.init_db()
        conn = sqlite3.connect(u.DB_NAME)
        rows = [
            ("t", NOW, "INCD", "https://f/il", "ISRAEL TAGGED CARD", "Raw", "High",
             "התרעת מערך הסייבר", None, "Israel"),
            ("t", NOW, "Cyber News IL", "https://f/legacy", "LEGACY HEBREW TAG CARD", "Raw", "High",
             "ידיעה ישנה", None, "ישראל"),
            ("t", NOW, "SecurityWeek", "https://f/other", "GENERAL CARD", "Raw", "Medium",
             "generic vendor story", None, "General"),
        ]
        for r in rows:
            conn.execute("INSERT INTO intel_reports (timestamp,published_at,source,url,title,"
                         "category,severity,summary,actor_tag,tags) VALUES (?,?,?,?,?,?,?,?,?,?)", r)
        conn.commit(); conn.close()

        from streamlit.testing.v1 import AppTest
        at = AppTest.from_file(APP, default_timeout=60)
        for k in SECRET_KEYS:
            at.secrets[k] = ""
        at.run()
        assert len(at.exception) == 0, [e.value for e in at.exception]
        at.radio(key="feed_tag_filter").set_value("Israel").run()
        assert len(at.exception) == 0, [e.value for e in at.exception]
        body = "\n".join(m.value for m in at.markdown)
        assert "ISRAEL TAGGED CARD" in body, "Israel-tagged card missing under Israel filter"
        assert "GENERAL CARD" not in body, "non-Israel card leaked into the Israel filter"
