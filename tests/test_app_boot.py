"""UI boot regression — runs the REAL app.py end-to-end via Streamlit AppTest.

Encodes the lesson "a green unit suite != a working app": this test actually
executes every top-level screen. Network is stubbed so the boot is hermetic;
secrets are injected so st.secrets does not raise (the no-secrets crash, F1, is
fixed and tested separately in Phase 1).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(REPO, "app.py")

SECRET_KEYS = ("groq_key", "vt_key", "urlscan_key", "abuseipdb_key", "gemini_key")


def _make_app(monkeypatch, tmp_path):
    import utils

    async def _no_network(*args, **kwargs):
        return [], []

    # Hermetic + fast: no live feeds during boot
    monkeypatch.setattr(utils.CTICollector, "get_all_data", _no_network)
    # init_db() (module-level in app.py) writes cti_dashboard.db to CWD
    monkeypatch.chdir(tmp_path)

    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(APP, default_timeout=60)
    for k in SECRET_KEYS:
        at.secrets[k] = ""  # present-but-empty: AI/enrichment simply disabled
    return at


def test_app_boots_without_exception(monkeypatch, tmp_path):
    at = _make_app(monkeypatch, tmp_path)
    at.run()
    assert len(at.exception) == 0, f"app.py raised on boot: {[e.value for e in at.exception]}"


def test_app_renders_five_tabs(monkeypatch, tmp_path):
    at = _make_app(monkeypatch, tmp_path)
    at.run()
    assert len(at.exception) == 0, f"app.py raised on boot: {[e.value for e in at.exception]}"
    assert len(at.tabs) == 5  # Live Feed, Live IOC, Threat Actors, Investigation Lab, Attack Map


def test_app_shows_operations_title(monkeypatch, tmp_path):
    at = _make_app(monkeypatch, tmp_path)
    at.run()
    assert len(at.exception) == 0, f"app.py raised on boot: {[e.value for e in at.exception]}"
    titles = [t.value for t in at.title]
    assert "Operations Dashboard" in titles


def test_app_renders_feed_with_data(monkeypatch, tmp_path):
    """De-risk the pandas major-version jump (2.x -> 3.x): the feed render path
    (read_sql_query -> to_datetime -> sort_values -> drop_duplicates -> iterrows
    -> HTML card) is NOT exercised by an empty-DB boot. Seed one row and assert
    the card renders without raising.
    """
    import datetime
    import sqlite3
    import utils

    async def _no_network(*args, **kwargs):
        return [], []

    monkeypatch.setattr(utils.CTICollector, "get_all_data", _no_network)
    monkeypatch.chdir(tmp_path)
    utils.init_db()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn = sqlite3.connect(utils.DB_NAME)
    conn.execute(
        "INSERT INTO intel_reports "
        "(timestamp,published_at,source,url,title,category,severity,summary,actor_tag,tags) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (now, now, "TheHackerNews", "https://example.test/a1", "TEST FEED ITEM",
         "News", "High", "unit-test summary line", None, "מחקר"),
    )
    conn.commit()
    conn.close()

    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(APP, default_timeout=60)
    for k in SECRET_KEYS:
        at.secrets[k] = ""
    at.run()
    assert len(at.exception) == 0, f"feed render raised: {[e.value for e in at.exception]}"
    assert any("TEST FEED ITEM" in m.value for m in at.markdown), "feed card was not rendered"


def test_app_renders_feed_with_mixed_timezones(monkeypatch, tmp_path):
    """Regression: real multi-source feeds carry mixed UTC offsets (Telegram UTC +
    RSS Israel time). pandas 3.0's to_datetime raises 'Mixed timezones' unless
    utc=True — caught by the live UI smoke, not the single-row unit test."""
    import datetime
    import sqlite3
    import utils

    async def _no_network(*args, **kwargs):
        return [], []

    monkeypatch.setattr(utils.CTICollector, "get_all_data", _no_network)
    monkeypatch.chdir(tmp_path)
    utils.init_db()
    conn = sqlite3.connect(utils.DB_NAME)
    # Dates must stay inside init_db()'s HISTORY_DAYS retention window, else the
    # boot-time prune deletes them. Anchor to now but keep DIFFERENT tz offsets
    # (+03:00 vs +00:00) so the mixed-timezone to_datetime(utc=True) path is hit.
    base = datetime.datetime.now(datetime.timezone.utc)
    a_il = (base - datetime.timedelta(hours=1)).astimezone(
        datetime.timezone(datetime.timedelta(hours=3))).isoformat()
    b_utc = (base - datetime.timedelta(hours=2)).isoformat()
    rows = [
        ("t", a_il, "TheHackerNews", "https://x.test/1", "Item A", "News", "High", "s", None, "General"),
        ("t", b_utc, "BleepingComputer", "https://x.test/2", "Item B", "News", "Medium", "s", None, "General"),
    ]
    for r in rows:
        conn.execute(
            "INSERT INTO intel_reports (timestamp,published_at,source,url,title,category,severity,summary,actor_tag,tags)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)", r)
    conn.commit()
    conn.close()

    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file(APP, default_timeout=60)
    for k in SECRET_KEYS:
        at.secrets[k] = ""
    at.run()
    assert len(at.exception) == 0, f"mixed-tz feed render raised: {[e.value for e in at.exception]}"
    assert any("Item A" in m.value for m in at.markdown)
    assert any("Item B" in m.value for m in at.markdown)
