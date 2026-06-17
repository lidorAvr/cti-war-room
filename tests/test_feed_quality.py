"""Feed quality (Phase 4e): marketing/off-topic filtering + per-source cap."""
import os
import sys
import asyncio

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils  # noqa: E402


class TestIsNoise:
    def test_marketing_dropped_for_any_source(self):
        # telegram marketing posts carry the marker in their (snippet) title
        item = {"title": "- תוכן שיווקי - הצטרפו ל-SOC שלנו", "summary": "...", "source": "Cyber News IL"}
        assert utils.is_noise(item) is True

    def test_promo_english_marker_dropped(self):
        assert utils.is_noise({"title": "Sponsored: a new SOC platform", "summary": "x", "source": "GBHackers"}) is True

    def test_sponsored_in_body_only_is_kept(self):
        # real articles whose body contains boilerplate 'sponsored' must NOT be dropped
        item = {"title": "North Korean NarwhalRAT malware deployed via fake alerts",
                "summary": "... related: sponsored ...", "source": "TheHackerNews"}
        assert utils.is_noise(item) is False

    def test_general_source_offtopic_dropped(self):
        item = {"title": "חברה גייסה 20 מיליון דולר", "summary": "סבב גיוס A להרחבת פעילות", "source": "People & Computers"}
        assert utils.is_noise(item) is True

    def test_general_source_cyber_kept(self):
        item = {"title": "מתקפת סייבר על בנק ישראלי", "summary": "דליפת מידע ופישינג", "source": "People & Computers"}
        assert utils.is_noise(item) is False

    def test_dedicated_source_kept_even_if_offtopic(self):
        # dedicated CTI sources are trusted as-is (no keyword requirement)
        assert utils.is_noise({"title": "Company raises funding", "summary": "business", "source": "BleepingComputer"}) is False


class TestCapPerSource:
    def test_caps_high_volume_source(self):
        rows = [{"source": "A", "x": i} for i in range(15)] + [{"source": "B", "x": i} for i in range(5)]
        out = utils.cap_per_source(pd.DataFrame(rows), 10)
        counts = out["source"].value_counts().to_dict()
        assert counts["A"] == 10
        assert counts["B"] == 5

    def test_preserves_order(self):
        rows = [{"source": "A", "n": 0}, {"source": "B", "n": 1}, {"source": "A", "n": 2}]
        out = utils.cap_per_source(pd.DataFrame(rows), 10)
        assert list(out["n"]) == [0, 1, 2]

    def test_empty_df_is_safe(self):
        assert utils.cap_per_source(pd.DataFrame(), 10).empty


class TestTitleDedup:
    """Why INCD posts need per-post titles: the title-similarity de-dup collapses
    identical titles, which previously hid all-but-one INCD alert."""

    def _items(self, t1, t2):
        return [
            {"title": t1, "url": "https://t.me/a/1", "date": "2026-06-15T00:00:00", "source": "INCD", "summary": "one"},
            {"title": t2, "url": "https://t.me/a/2", "date": "2026-06-15T00:00:00", "source": "INCD", "summary": "two"},
        ]

    def test_distinct_titles_both_survive(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        utils.init_db()
        out = asyncio.run(utils.AIBatchProcessor("").analyze_batch(
            self._items("INCD: phishing SMS campaign", "INCD: ransomware advisory")))
        assert len(out) == 2

    def test_identical_titles_collapse(self, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        utils.init_db()
        out = asyncio.run(utils.AIBatchProcessor("").analyze_batch(
            self._items("INCD Cyber Alert", "INCD Cyber Alert")))
        assert len(out) == 1
