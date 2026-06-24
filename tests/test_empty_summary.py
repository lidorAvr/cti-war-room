"""Empty-AI-summary fallback.

Groq occasionally returns the bullet template with every section blank
(e.g. FortiBleed / Xsolis in the owner's live feed showed
'• **תמונת מצב**: <br>• **ממצאים טכניים**: <br>• **משמעויות**:'). Such items
should fall back to their raw source text (like a RAW card) instead of being
shown as empty bullets.
"""
import asyncio
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils  # noqa: E402

RECENT = "2026-06-24T10:00:00+00:00"
EMPTY_TEMPLATE = "• **תמונת מצב**: <br>• **ממצאים טכניים**: <br>• **משמעויות**:"


def _fake_groq(summary_for_all):
    async def _fake(key, prompt, **kwargs):
        ids = [int(m) for m in re.findall(r"ID:(\d+)", prompt)]
        items = [{"id": i, "title": f"כותרת מקצועית {i}", "summary": summary_for_all} for i in ids]
        return json.dumps({"items": items})
    return _fake


def _items():
    return [
        {"title": "Acme hit by ransomware", "url": "https://a/1", "date": RECENT,
         "source": "BleepingComputer", "summary": "Acme Corp suffered a ransomware attack affecting operations."},
        {"title": "New RCE in Foo software", "url": "https://a/2", "date": RECENT,
         "source": "TheHackerNews", "summary": "A critical RCE was found in Foo CVE-2026-12345 affecting servers."},
    ]


class TestIsEmptyAiSummary:
    def test_empty_template_detected(self):
        assert utils._is_empty_ai_summary(EMPTY_TEMPLATE) is True

    def test_blank_detected(self):
        assert utils._is_empty_ai_summary("") is True
        assert utils._is_empty_ai_summary("   \n  ") is True

    def test_real_hebrew_summary_kept(self):
        assert utils._is_empty_ai_summary("• **תמונת מצב**: ארגון ספג מתקפת כופרה גדולה.") is False

    def test_short_technical_content_kept(self):
        assert utils._is_empty_ai_summary("• **תמונת מצב**: CVE-2026-12345 RCE") is False


class TestAnalyzeBatchFallback:
    def test_empty_ai_output_falls_back_to_raw(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        utils.init_db()
        monkeypatch.setattr(utils, "query_groq_api", _fake_groq(EMPTY_TEMPLATE))
        out = asyncio.run(utils.AIBatchProcessor("test-key").analyze_batch(_items()))
        assert len(out) == 2
        assert all(r["category"] == "Raw" for r in out), [r["category"] for r in out]
        # the fallback preserves the ORIGINAL source text, not empty bullets
        by_url = {r["url"]: r["summary"] for r in out}
        assert "ransomware attack" in by_url["https://a/1"]
        assert "CVE-2026-12345" in by_url["https://a/2"]
        assert all("**תמונת מצב**" not in s for s in by_url.values())

    def test_real_ai_output_stays_news(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        utils.init_db()
        monkeypatch.setattr(utils, "query_groq_api",
                            _fake_groq("• **תמונת מצב**: ארגון ספג מתקפת כופרה משמעותית."))
        out = asyncio.run(utils.AIBatchProcessor("test-key").analyze_batch(_items()))
        assert len(out) == 2
        assert all(r["category"] == "News" for r in out), [r["category"] for r in out]
        assert all("כופרה" in r["summary"] for r in out)


class TestEndToEnd:
    """Full pipeline through the REAL app.py: boot -> perform_update ->
    analyze_batch (Groq returns the empty template) -> save_reports -> feed
    render. The feed must show the source text, never the empty AI bullets."""

    def test_empty_ai_renders_source_text_not_empty_bullets(self, monkeypatch, tmp_path):
        raw_item = {"title": "Globex breach exposes data", "url": "https://e2e/1", "date": RECENT,
                    "source": "BleepingComputer",
                    "summary": "Globex confirmed a breach exposing customer records this week."}

        async def _net(*a, **k):
            return [raw_item], [{"source": "BleepingComputer", "ok": True, "count": 1}]

        monkeypatch.setattr(utils.CTICollector, "get_all_data", _net)
        monkeypatch.setattr(utils, "query_groq_api", _fake_groq(EMPTY_TEMPLATE))
        monkeypatch.chdir(tmp_path)

        from streamlit.testing.v1 import AppTest
        repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        at = AppTest.from_file(os.path.join(repo, "app.py"), default_timeout=60)
        for k in ("groq_key", "vt_key", "urlscan_key", "abuseipdb_key", "gemini_key"):
            at.secrets[k] = ""
        at.secrets["groq_key"] = "test-key"  # truthy -> exercise the AI path
        at.run()
        assert len(at.exception) == 0, [e.value for e in at.exception]
        assert any("Globex confirmed a breach" in m.value for m in at.markdown), "source text missing"
        assert all("**תמונת מצב**" not in m.value for m in at.markdown), "empty AI template leaked to the UI"
