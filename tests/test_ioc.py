"""Live IOC feed (Phase 7).

The hard requirement: IOC values may feed BLOCKING rules, so they must be
extracted deterministically from RAW source text (regex + validation) — never
invented, and never taken from AI output. Precision beats recall: publisher and
ubiquitous-legit domains are denylisted, private/reserved IPs are rejected.
"""
import datetime
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(REPO, "app.py")
SECRET_KEYS = ("groq_key", "vt_key", "urlscan_key", "abuseipdb_key", "gemini_key")


def _values(iocs, typ=None):
    return [i["value"] for i in iocs if typ is None or i["type"] == typ]


class TestExtractIocs:
    def test_refanged_domain_and_url(self):
        iocs = utils.extract_iocs("Payload served from hxxp://evil-updates[.]com/load.ps1")
        assert "evil-updates.com" in _values(iocs, "domain")
        assert any(v.startswith("http://evil-updates.com/") for v in _values(iocs, "url"))

    def test_public_ip_found(self):
        iocs = utils.extract_iocs("C2 traffic observed to 185.220.101.5 over 443")
        assert "185.220.101.5" in _values(iocs, "ip")

    def test_private_and_loopback_ips_rejected(self):
        iocs = utils.extract_iocs("connects to 192.168.1.10, 10.0.0.7 and 127.0.0.1")
        assert _values(iocs, "ip") == []

    def test_version_like_ip_rejected(self):
        # product versions look like IPs (e.g. Chrome 120.0.0.0) — trailing .0 is rejected
        assert _values(utils.extract_iocs("fixed in version 120.0.0.0"), "ip") == []

    def test_publisher_domain_rejected(self):
        iocs = utils.extract_iocs("Details: https://www.bleepingcomputer.com/news/security/x/")
        assert iocs == []

    def test_ubiquitous_legit_domain_rejected(self):
        assert utils.extract_iocs("code hosted on github.com and t.me/somechannel") == []

    def test_hashes_found(self):
        sha256 = "a" * 63 + "b"
        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        iocs = utils.extract_iocs(f"dropper {sha256} and stager {md5}")
        assert sha256 in _values(iocs, "sha256")
        assert md5 in _values(iocs, "md5")

    def test_cve_found_and_uppercased(self):
        assert "CVE-2026-20230" in _values(utils.extract_iocs("exploits cve-2026-20230 in the wild"), "cve")

    def test_benign_text_yields_nothing(self):
        # NO invention: text without indicators must produce zero IOCs
        assert utils.extract_iocs("Microsoft released a patch on Tuesday for its cloud platform.") == []

    def test_file_names_are_not_domains(self):
        assert utils.extract_iocs("the dropper malware.exe writes report.pdf and utils.py") == []

    def test_url_shortener_rejected(self):
        # caught live: t.co leaked from an article link — a shortener is never blockable
        assert utils.extract_iocs("read more at https://t.co/abc123 or bit.ly/xyz") == []


class TestPurgeDenied:
    def test_retroactive_purge_of_newly_denied_domain(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        utils.init_db()
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        utils.save_iocs([
            {"value": "t.co", "ioc_type": "domain", "severity": "Medium", "tags": "General",
             "israel": 0, "source": "X", "report_url": "https://p/1", "report_title": "t", "first_seen": now},
            {"value": "evil-updates.com", "ioc_type": "domain", "severity": "High", "tags": "Malware",
             "israel": 0, "source": "X", "report_url": "https://p/2", "report_title": "t", "first_seen": now},
        ])
        utils._purge_denied_iocs()
        left = [r[0] for r in sqlite3.connect(utils.DB_NAME).execute("SELECT value FROM iocs").fetchall()]
        assert "t.co" not in left, "denylisted IOC survived the purge"
        assert "evil-updates.com" in left, "legitimate IOC was wrongly purged"


class TestIsraelPriority:
    def test_incd_source_flagged(self):
        assert utils.is_israel_related("generic alert text", "INCD") is True

    def test_hebrew_israel_marker_flagged(self):
        assert utils.is_israel_related("מתקפה על ארגון בישראל", "BleepingComputer") is True

    def test_il_domain_ioc_flagged(self):
        assert utils.is_israel_related("phishing kit", "Krebs", ["evil-bank.co.il"]) is True

    def test_unrelated_not_flagged(self):
        assert utils.is_israel_related("ransomware hits a US hospital", "Krebs", ["1.2.3.4"]) is False


class TestIocPipeline:
    RECENT = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def test_save_reports_extracts_from_raw_text(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        utils.init_db()
        raw = [{"title": "New stealer targets Israel", "url": "https://r/1", "date": self.RECENT,
                "source": "BleepingComputer",
                "summary": "The C2 at 185.220.101.5 serves hxxp://evil-updates[.]com using CVE-2026-11111."}]
        analyzed = [{"category": "Raw", "severity": "High", "title": raw[0]["title"],
                     "summary": raw[0]["summary"], "published_at": self.RECENT,
                     "source": "BleepingComputer", "url": "https://r/1", "actor_tag": None,
                     "tags": "Israel"}]
        utils.save_reports(raw, analyzed)
        rows = sqlite3.connect(utils.DB_NAME).execute(
            "SELECT value, ioc_type, israel, severity FROM iocs").fetchall()
        vals = {r[0] for r in rows}
        assert "185.220.101.5" in vals and "evil-updates.com" in vals and "CVE-2026-11111" in vals
        assert all(r[2] == 1 for r in rows), "Israel priority flag missing"
        assert all(r[3] == "High" for r in rows)

    def test_backfill_skips_ai_rows(self, monkeypatch, tmp_path):
        """AI ('News') summaries are model output — they must NOT feed the IOC list."""
        monkeypatch.chdir(tmp_path)
        utils.init_db()
        conn = sqlite3.connect(utils.DB_NAME)
        rows = [
            ("t", self.RECENT, "SecurityWeek", "https://b/raw", "Raw report", "Raw", "Medium",
             "beacons to 185.199.229.156 daily", None, "Malware"),
            ("t", self.RECENT, "SecurityWeek", "https://b/ai", "AI report", "News", "Medium",
             "• **תמונת מצב**: תקיפה דרך 8.8.8.8 (טקסט מודל — לא לחלץ)", None, "Malware"),
        ]
        for r in rows:
            conn.execute("INSERT INTO intel_reports (timestamp,published_at,source,url,title,"
                         "category,severity,summary,actor_tag,tags) VALUES (?,?,?,?,?,?,?,?,?,?)", r)
        conn.commit(); conn.close()
        utils.backfill_iocs()
        got = sqlite3.connect(utils.DB_NAME).execute("SELECT value, report_url FROM iocs").fetchall()
        assert ("185.199.229.156", "https://b/raw") in got
        assert all(u != "https://b/ai" for _, u in got), "IOC was extracted from AI text!"


class TestIocUI:
    def _boot(self, monkeypatch, tmp_path, seed=True):
        import utils as u

        async def _no_network(*a, **k):
            return [], []

        monkeypatch.setattr(u.CTICollector, "get_all_data", _no_network)
        monkeypatch.chdir(tmp_path)
        u.init_db()
        if seed:
            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            conn = sqlite3.connect(u.DB_NAME)
            conn.execute("INSERT INTO intel_reports (timestamp,published_at,source,url,title,"
                         "category,severity,summary,actor_tag,tags) VALUES (?,?,?,?,?,?,?,?,?,?)",
                         ("t", now, "BleepingComputer", "https://rep/1", "SEEDED REPORT", "Raw",
                          "High", "C2 at 185.220.101.5", None, "Malware"))
            conn.commit(); conn.close()
            u.save_iocs([{"value": "185.220.101.5", "ioc_type": "ip", "severity": "High",
                          "tags": "Malware", "israel": 1, "source": "BleepingComputer",
                          "report_url": "https://rep/1", "report_title": "SEEDED REPORT",
                          "first_seen": now}])
        from streamlit.testing.v1 import AppTest
        at = AppTest.from_file(APP, default_timeout=60)
        for k in SECRET_KEYS:
            at.secrets[k] = ""
        at.run()
        assert len(at.exception) == 0, [e.value for e in at.exception]
        return at

    def test_app_has_five_tabs(self, monkeypatch, tmp_path):
        at = self._boot(monkeypatch, tmp_path, seed=False)
        assert len(at.tabs) == 5

    def test_ioc_value_copyable_in_ui(self, monkeypatch, tmp_path):
        # st.code = the copy-button widget; the IOC value must be rendered in one
        at = self._boot(monkeypatch, tmp_path)
        codes = [c.value for c in at.code]
        assert "185.220.101.5" in codes, f"IOC not rendered in a copyable block: {codes}"

    def test_feed_card_carries_ioc_badge(self, monkeypatch, tmp_path):
        at = self._boot(monkeypatch, tmp_path)
        assert any("🎯 1 IOC" in m.value for m in at.markdown), "IOC badge missing from feed card"
