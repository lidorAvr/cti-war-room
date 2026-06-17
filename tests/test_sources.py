"""Source registry + RSS-parsing robustness (Phase 4 source expansion)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils  # noqa: E402


def test_sources_well_formed_and_unique():
    seen = set()
    for s in utils.CTICollector.SOURCES:
        assert s.get("name"), s
        assert s.get("url"), s
        assert s["type"] in ("rss", "json", "telegram"), s
        assert s["url"] not in seen, f"duplicate source url: {s['url']}"
        seen.add(s["url"])
    assert len(utils.CTICollector.SOURCES) >= 20


def test_entry_summary_missing_does_not_crash():
    class E:  # an entry-like object with no summary/description/content
        pass
    assert utils._entry_summary(E()) == ""


def test_entry_summary_extracts_and_strips_html():
    class E:
        pass
    e = E()
    e.summary = "<p>hello <b>world</b></p>"
    assert utils._entry_summary(e).strip() == "hello world"


def test_entry_summary_falls_back_to_description():
    class E:
        pass
    e = E()
    e.description = "<div>fallback desc</div>"
    assert "fallback desc" in utils._entry_summary(e)
