"""Phase 1 (reliability hardening) regression tests:
F1 — app boots with NO secrets file (the crash found via real-UI run).
F2 — the end-of-life Gemini layer is gone.
F3 — feed/source failures are surfaced (not silently swallowed).
"""
import os
import sys
import asyncio

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(REPO, "app.py")

import utils  # noqa: E402


class _RaisingSecrets:
    """Mimics st.secrets when there is no secrets.toml at all: .get() raises."""
    def get(self, *args, **kwargs):
        from streamlit.errors import StreamlitSecretNotFoundError
        raise StreamlitSecretNotFoundError("no secrets file (test)")


# ----------------------------------------------------------------- F1: secrets
def test_get_secret_returns_default_when_no_secrets_file(monkeypatch):
    monkeypatch.setattr(utils.st, "secrets", _RaisingSecrets())
    assert utils.get_secret("groq_key", "") == ""
    assert utils.get_secret("missing", "fallback") == "fallback"


def test_app_boots_without_secrets(monkeypatch, tmp_path):
    """F1 regression: app must NOT crash on boot when no secrets file exists."""
    async def _no_network(*a, **k):
        return [], []
    monkeypatch.setattr(utils.CTICollector, "get_all_data", _no_network)
    monkeypatch.setattr(utils.st, "secrets", _RaisingSecrets())
    monkeypatch.chdir(tmp_path)

    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file(APP, default_timeout=60)
    at.run()  # deliberately NOT injecting at.secrets
    assert len(at.exception) == 0, f"app crashed without secrets: {[e.value for e in at.exception]}"
    assert len(at.tabs) == 4


# ------------------------------------------------------------- F2: Gemini gone
def test_gemini_layer_removed():
    assert not hasattr(utils, "polish_with_gemini"), "polish_with_gemini should be removed"
    assert not hasattr(utils, "genai"), "google.generativeai should no longer be imported"


# ------------------------------------------------- F3: source failures visible
def test_get_all_data_returns_items_and_statuses(monkeypatch):
    async def _fake_fetch(self, session, source):
        ok = source["name"] != "Unit 42"  # simulate one dead source
        return {
            "source": source["name"], "url": source["url"], "ok": ok,
            "items": ([{"x": 1}] if ok else []),
            "error": (None if ok else "boom"),
        }
    monkeypatch.setattr(utils.CTICollector, "fetch_item", _fake_fetch)

    items, statuses = asyncio.run(utils.CTICollector().get_all_data())
    assert len(statuses) == len(utils.CTICollector.SOURCES)
    assert all(("ok" in s and "count" in s and "error" in s) for s in statuses)
    failed = [s for s in statuses if not s["ok"]]
    assert failed and failed[0]["error"] == "boom"      # failure is surfaced
    assert len(items) == sum(1 for s in statuses if s["ok"])  # only ok sources add items


def test_sidebar_surfaces_failed_source(monkeypatch, tmp_path):
    """F3 (UI): a failed source must be visible to the analyst, not silent."""
    async def _no_network(*a, **k):
        return [], []
    monkeypatch.setattr(utils.CTICollector, "get_all_data", _no_network)
    monkeypatch.chdir(tmp_path)

    from streamlit.testing.v1 import AppTest
    at = AppTest.from_file(APP, default_timeout=60)
    for k in ("groq_key", "vt_key", "urlscan_key", "abuseipdb_key"):
        at.secrets[k] = "x"                       # keys present -> no missing-keys banner
    at.session_state["booted"] = True             # skip boot so our status isn't overwritten
    at.session_state["source_status"] = [
        {"source": "BleepingComputer", "url": "u", "ok": True, "count": 5, "error": None},
        {"source": "Unit 42", "url": "u", "ok": False, "count": 0, "error": "HTTP 503"},
    ]
    at.run()
    assert len(at.exception) == 0, f"sidebar render raised: {[e.value for e in at.exception]}"
    captions = " ".join(c.value for c in at.caption)
    assert "Unit 42" in captions and "HTTP 503" in captions
