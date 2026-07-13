"""Dedicated IOC feeds (Phase 8): ThreatFox / URLhaus / OpenPhish.

Sample payloads mirror the REAL shapes probed live on 2026-07-13. Parsing is a
straight deterministic transform (no LLM). The legit-domain denylist stays
enforced (never let github.com & co. into a blocking feed), but the news-text
TLD allowlist does NOT apply — real C2s sit on exotic TLDs (seen live: .garden).
"""
import asyncio
import datetime
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils  # noqa: E402

THREATFOX = {
    "101": [{"ioc_value": "63mkau.deryuga-sablist.garden", "ioc_type": "domain",
             "threat_type": "botnet_cc", "malware_printable": "ClearFake",
             "confidence_level": 90, "first_seen_utc": "2026-07-13 08:16:32"}],
    "102": [{"ioc_value": "185.220.101.7:4444", "ioc_type": "ip:port",
             "threat_type": "botnet_cc", "malware_printable": "Sliver",
             "confidence_level": 50, "first_seen_utc": "2026-07-13 07:00:00"}],
    "103": [{"ioc_value": "192.168.1.50:8080", "ioc_type": "ip:port",  # private -> dropped
             "threat_type": "botnet_cc", "malware_printable": "x",
             "confidence_level": 90, "first_seen_utc": "2026-07-13 06:00:00"}],
    "104": [{"ioc_value": "a" * 64, "ioc_type": "sha256_hash",
             "threat_type": "payload", "malware_printable": "Lumma",
             "confidence_level": 100, "first_seen_utc": "2026-07-13 05:00:00"}],
    "105": [{"ioc_value": "github.com", "ioc_type": "domain",  # denylisted -> dropped
             "threat_type": "botnet_cc", "malware_printable": "x",
             "confidence_level": 90, "first_seen_utc": "2026-07-13 04:00:00"}],
}

URLHAUS = {
    "201": [{"url": "http://91.92.242.236/files/file_84ca.exe", "url_status": "online",
             "threat": "malware_download", "tags": ["exe", "TA578"],
             "urlhaus_link": "https://urlhaus.abuse.ch/url/201/",
             "dateadded": "2026-07-13 08:00:17 UTC"}],
    "202": [{"url": "https://evil.jadoou.skin/x", "url_status": "offline",
             "threat": "malware_download", "tags": [],
             "urlhaus_link": "https://urlhaus.abuse.ch/url/202/",
             "dateadded": "2026-07-13 07:30:00 UTC"}],
    "203": [{"url": "https://github.com/evil/repo/raw/payload.exe", "url_status": "online",
             "threat": "malware_download", "tags": [],  # denylisted host -> dropped
             "urlhaus_link": "https://urlhaus.abuse.ch/url/203/",
             "dateadded": "2026-07-13 07:00:00 UTC"}],
}

OPENPHISH = "\n".join([
    "https://phish-login.evil-site.top/account",
    "not a url line",
    "http://bank-verify.co.il.fake-portal.cc/login",
])


class TestParseThreatfox:
    def test_exotic_tld_kept_denylist_enforced(self):
        vals = {e["value"]: e for e in utils._parse_threatfox(THREATFOX)}
        assert "63mkau.deryuga-sablist.garden" in vals   # no TLD allowlist for feeds
        assert "github.com" not in vals                   # denylist still applies

    def test_ip_port_split_and_private_dropped(self):
        vals = {e["value"]: e for e in utils._parse_threatfox(THREATFOX)}
        assert "185.220.101.7" in vals and vals["185.220.101.7"]["ioc_type"] == "ip"
        assert not any(v.startswith("192.168.") for v in vals)

    def test_confidence_maps_to_severity(self):
        vals = {e["value"]: e for e in utils._parse_threatfox(THREATFOX)}
        assert vals["63mkau.deryuga-sablist.garden"]["severity"] == "High"   # conf 90
        assert vals["185.220.101.7"]["severity"] == "Medium"                 # conf 50

    def test_hash_typed_and_report_link_built(self):
        vals = {e["value"]: e for e in utils._parse_threatfox(THREATFOX)}
        h = vals["a" * 64]
        assert h["ioc_type"] == "sha256"
        assert h["report_url"] == "https://threatfox.abuse.ch/ioc/104/"
        assert "Lumma" in h["report_title"]


class TestParseUrlhaus:
    def test_online_high_offline_medium(self):
        out = {e["value"]: e for e in utils._parse_urlhaus(URLHAUS)}
        assert out["http://91.92.242.236/files/file_84ca.exe"]["severity"] == "High"
        assert out["https://evil.jadoou.skin/x"]["severity"] == "Medium"

    def test_denylisted_host_dropped(self):
        out = [e["value"] for e in utils._parse_urlhaus(URLHAUS)]
        assert not any("github.com" in v for v in out)

    def test_reference_link_kept(self):
        out = {e["value"]: e for e in utils._parse_urlhaus(URLHAUS)}
        assert out["http://91.92.242.236/files/file_84ca.exe"]["report_url"] == "https://urlhaus.abuse.ch/url/201/"


class TestParseOpenphish:
    def test_urls_parsed_junk_skipped(self):
        out = utils._parse_openphish(OPENPHISH)
        vals = [e["value"] for e in out]
        assert "https://phish-login.evil-site.top/account" in vals
        assert all(v.startswith("http") for v in vals)

    def test_phishing_high_and_il_flagged(self):
        out = {e["value"]: e for e in utils._parse_openphish(OPENPHISH)}
        e = out["https://phish-login.evil-site.top/account"]
        assert e["severity"] == "High" and e["tags"] == "Phishing"

    def test_cap_respected(self):
        many = "\n".join(f"https://phish{i}.evil.top/" for i in range(100))
        assert len(utils._parse_openphish(many)) == utils.MAX_FEED_IOCS


class TestHourlyGate:
    def test_due_then_gated(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        utils.init_db()
        assert utils._ioc_feed_due("ThreatFox") is True
        utils._mark_ioc_feed_fetched("ThreatFox")
        assert utils._ioc_feed_due("ThreatFox") is False
        assert utils._ioc_feed_due("URLhaus") is True  # independent per feed


class _FeedResp:
    def __init__(self, payload, text=None):
        self.status, self._payload, self._text = 200, payload, text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def json(self, content_type=None):
        return self._payload

    async def text(self):
        return self._text


class _FeedSession:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def get(self, url, **kw):
        if "threatfox" in url:
            return _FeedResp(THREATFOX)
        if "urlhaus" in url:
            return _FeedResp(URLHAUS)
        return _FeedResp(None, text=OPENPHISH)


@pytest.mark.real_ioc_feeds
class TestFetchIocFeeds:
    def test_end_to_end_saves_and_gates(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        utils.init_db()
        monkeypatch.setattr(utils.aiohttp, "ClientSession", lambda *a, **k: _FeedSession())

        statuses = asyncio.run(utils.fetch_ioc_feeds())
        assert [s["source"] for s in statuses] == ["ThreatFox", "URLhaus", "OpenPhish"]
        assert all(s["ok"] for s in statuses)

        conn = sqlite3.connect(utils.DB_NAME)
        by_src = dict(conn.execute("SELECT source, COUNT(*) FROM iocs GROUP BY source").fetchall())
        conn.close()
        assert by_src["ThreatFox"] == 3   # garden domain + ip + sha256 (private & github dropped)
        assert by_src["URLhaus"] == 2     # online + offline (github dropped)
        assert by_src["OpenPhish"] == 2

        # hourly gate: an immediate second run fetches nothing
        assert asyncio.run(utils.fetch_ioc_feeds()) == []
