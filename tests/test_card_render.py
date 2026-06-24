"""Feed-card render regression.

The bug: AI-summarized cards rendered as literal HTML inside a Markdown code
block, while RAW cards looked fine. Two root causes, both fixed in
``get_feed_card_html``:

1. The returned f-string was indented and, for AI cards, ``raw_badge`` was empty
   -> a whitespace-only line. Streamlit's Markdown read that as a blank line,
   closed the HTML block, and turned the following 4+ space-indented lines into a
   code block. Fix: collapse the HTML to a single un-indented line.
2. ``**bold**`` stayed literal because Markdown does not process markdown inside
   an HTML block. Fix: convert ``**x**`` -> ``<strong>x</strong>`` first.

This runs the REAL app.py via AppTest so it guards the actual st.markdown call.
"""
import datetime
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(REPO, "app.py")

SECRET_KEYS = ("groq_key", "vt_key", "urlscan_key", "abuseipdb_key", "gemini_key")

# AI summary as Groq emits it: markdown bold + newline-separated bullets.
AI_SUMMARY = "• **תמונת מצב**: בדיקה.\n• **ממצאים טכניים**: אין.\n• **משמעויות**: נמוכה."


def _run_with_rows(monkeypatch, tmp_path, rows):
    import utils

    async def _no_network(*args, **kwargs):
        return [], []

    monkeypatch.setattr(utils.CTICollector, "get_all_data", _no_network)
    monkeypatch.chdir(tmp_path)
    utils.init_db()
    conn = sqlite3.connect(utils.DB_NAME)
    for r in rows:
        conn.execute(
            "INSERT INTO intel_reports (timestamp,published_at,source,url,title,"
            "category,severity,summary,actor_tag,tags) VALUES (?,?,?,?,?,?,?,?,?,?)", r)
    conn.commit()
    conn.close()

    from streamlit.testing.v1 import AppTest

    at = AppTest.from_file(APP, default_timeout=60)
    for k in SECRET_KEYS:
        at.secrets[k] = ""
    at.run()
    assert len(at.exception) == 0, f"render raised: {[e.value for e in at.exception]}"
    return at


def _card(at, title):
    cards = [m.value for m in at.markdown if title in m.value]
    assert cards, f"card {title!r} was not rendered"
    return cards[0]


def test_ai_card_is_not_a_code_block(monkeypatch, tmp_path):
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    at = _run_with_rows(monkeypatch, tmp_path, [
        ("t", now, "TheHackerNews", "https://x.test/ai", "AI STYLE CARD",
         "News", "High", AI_SUMMARY, None, "Research"),
    ])
    card = _card(at, "AI STYLE CARD")
    # Single line -> Markdown cannot treat it as an indented code block.
    assert "\n" not in card, "card HTML still multi-line (will render as a code block)"
    assert card.lstrip().startswith("<div class=\"report-card\""), card[:60]


def test_ai_bold_is_converted_to_html(monkeypatch, tmp_path):
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    at = _run_with_rows(monkeypatch, tmp_path, [
        ("t", now, "TheHackerNews", "https://x.test/ai", "AI STYLE CARD",
         "News", "High", AI_SUMMARY, None, "Research"),
    ])
    card = _card(at, "AI STYLE CARD")
    assert "<strong>" in card, "** was not converted to <strong>"
    assert "**" not in card, "literal markdown ** leaked into the card"


def test_ai_newlines_become_single_br(monkeypatch, tmp_path):
    """The model sometimes emits '\\n   \\n' -> previously '<br>     <br>' gaps."""
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    messy = "• **א**: x\n   \n• **ב**: y"
    at = _run_with_rows(monkeypatch, tmp_path, [
        ("t", now, "TheHackerNews", "https://x.test/ai", "MESSY CARD",
         "News", "High", messy, None, "Research"),
    ])
    card = _card(at, "MESSY CARD")
    assert "<br>     <br>" not in card and "<br><br>" not in card


def test_raw_card_still_renders(monkeypatch, tmp_path):
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    at = _run_with_rows(monkeypatch, tmp_path, [
        ("t", now, "BleepingComputer", "https://x.test/raw", "RAW STYLE CARD",
         "raw", "Medium", "A plain raw English summary with no markdown.", None, "Malware"),
    ])
    card = _card(at, "RAW STYLE CARD")
    assert "\n" not in card
    assert "RAW · no AI" in card, "raw badge missing"
