"""Cross-source de-duplication + word-bounded low-value matching."""
import os
import sys
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils  # noqa: E402


class TestTitleMarkerBoundary:
    def test_ebook_not_matched_inside_facebook(self):
        # 'ebook' must NOT match inside 'Facebook'
        assert utils.is_low_value({"title": "Sniper Dz scams target users via fake Facebook offers"}) is False

    def test_appointed_not_matched_inside_disappointed(self):
        assert utils.is_low_value({"title": "Researchers disappointed by slow patching"}) is False

    def test_survey_title_dropped(self):
        assert utils.is_low_value({"title": "Survey: 94% of organizations were breached"}) is True

    def test_funding_title_dropped(self):
        assert utils.is_low_value({"title": "Acme raises $20M in Series B funding"}) is True

    def test_real_malware_title_kept(self):
        assert utils.is_low_value({"title": "Fake Microsoft alerts deploy NarwhalRAT malware"}) is False


class TestIsDuplicate:
    def test_shared_cve_is_duplicate(self):
        a = utils._signature({"title": "Cisco SD-WAN flaw exploited", "summary": "CVE-2026-20262"})
        b = utils._signature({"title": "CISA adds Cisco Catalyst bug to KEV", "summary": "CVE-2026-20262 active"})
        assert utils.is_duplicate(a, b) is True

    def test_token_overlap_is_duplicate(self):
        a = utils._signature({"title": "Oracle PeopleSoft zero-day exploited by ransomware gang", "summary": ""})
        b = utils._signature({"title": "ShinyHunters exploit Oracle PeopleSoft zero-day ransomware", "summary": ""})
        assert utils.is_duplicate(a, b) is True

    def test_unrelated_not_duplicate(self):
        a = utils._signature({"title": "Cisco SD-WAN flaw exploited", "summary": ""})
        b = utils._signature({"title": "New Android banking trojan spreads via Telegram", "summary": ""})
        assert utils.is_duplicate(a, b) is False


class TestAnalyzeBatchDedup:
    def test_same_cve_collapses_across_outlets(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        utils.init_db()
        items = [
            {"title": "Cisco SD-WAN flaw exploited in attacks", "url": "https://a/1", "date": "2026-06-15T00:00:00", "source": "BleepingComputer", "summary": "CVE-2026-20262 details and impact"},
            {"title": "CISA flags Cisco Catalyst SD-WAN bug", "url": "https://a/2", "date": "2026-06-15T00:00:00", "source": "TheHackerNews", "summary": "CVE-2026-20262 actively exploited in the wild now"},
            {"title": "KEV: CVE-2026-20262", "url": "https://a/3", "date": "2026-06-15T00:00:00", "source": "CISA", "summary": "CVE-2026-20262"},
        ]
        out = asyncio.run(utils.AIBatchProcessor("").analyze_batch(items))
        assert len(out) == 1  # three outlets, one story
