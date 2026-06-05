"""Graceful no-AI fallback: when there is no Groq key (or the API fails),
analyze_batch keeps the RAW fetched items so the feed shows real intel instead
of going blank.
"""
import os
import sys
import asyncio
import sqlite3
import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils  # noqa: E402


def test_keeps_raw_items_without_key(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    utils.init_db()
    proc = utils.AIBatchProcessor("")  # no Groq key
    items = [
        {"title": "Cisco SD-WAN zero-day exploited in attacks",
         "url": "https://example.test/cisco", "date": "2026-06-05T08:00:00",
         "source": "BleepingComputer", "summary": "Raw source body about active exploitation."},
        {"title": "New phishing campaign targets banks",
         "url": "https://example.test/phish", "date": "2026-06-05T09:00:00",
         "source": "INCD", "summary": "Credential theft via lookalike domains."},
    ]
    out = asyncio.run(proc.analyze_batch(items))
    assert len(out) == 2, "raw items must survive without AI"
    by_url = {o["url"]: o for o in out}
    assert by_url["https://example.test/cisco"]["title"] == "Cisco SD-WAN zero-day exploited in attacks"
    # rule-based severity still applies ("zero-day"/"exploited" -> High)
    assert by_url["https://example.test/cisco"]["severity"] == "High"
    # flagged as raw so the UI can mark it (no AI summary)
    assert all(o["category"] == "Raw" for o in out)


def test_empty_input_returns_empty():
    proc = utils.AIBatchProcessor("")
    assert asyncio.run(proc.analyze_batch([])) == []


def test_already_stored_items_not_re_added(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    utils.init_db()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    conn = sqlite3.connect(utils.DB_NAME)
    conn.execute(
        "INSERT INTO intel_reports (timestamp,published_at,source,url,title,category,severity,summary,actor_tag,tags)"
        " VALUES (?,?,?,?,?,?,?,?,?,?)",
        (now, now, "BleepingComputer", "https://example.test/dup", "Existing item", "Raw", "Medium", "x", None, "כללי"),
    )
    conn.commit()
    conn.close()
    proc = utils.AIBatchProcessor("")
    out = asyncio.run(proc.analyze_batch([
        {"title": "Existing item", "url": "https://example.test/dup", "date": now,
         "source": "BleepingComputer", "summary": "x"}
    ]))
    assert out == [], "already-stored items must not be re-added as duplicates"
