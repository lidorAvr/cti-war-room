"""Reliable AI everywhere (Phase 5).

- get_secret() falls back to an environment variable so AI/enrichment work
  without a project secrets.toml (Claude_Preview, cron, deploy).
- ConnectionManager.ping_groq() is a REAL reachability check (the old check_groq
  only validated the key *format*).
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils  # noqa: E402


class TestGetSecretEnvFallback:
    # Use a key NOT present in the repo's .streamlit/secrets.toml so st.secrets
    # can't satisfy it and the env-var fallback is what is exercised.
    def test_env_var_is_used(self, monkeypatch):
        monkeypatch.setenv("TEST_ONLY_KEY", "from-env-123")
        assert utils.get_secret("test_only_key") == "from-env-123"

    def test_default_when_absent(self, monkeypatch):
        monkeypatch.delenv("TEST_ONLY_KEY", raising=False)
        assert utils.get_secret("test_only_key", "fallback") == "fallback"

    def test_empty_string_when_no_default(self, monkeypatch):
        monkeypatch.delenv("TEST_ONLY_KEY", raising=False)
        assert utils.get_secret("test_only_key") == ""


class _FakeResp:
    def __init__(self, status):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _FakeSession:
    def __init__(self, status):
        self._status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    def get(self, *a, **k):
        return _FakeResp(self._status)


@pytest.mark.real_groq  # exercises the real ping_groq against a mocked aiohttp
class TestPingGroq:
    def test_missing_key(self):
        assert asyncio.run(utils.ConnectionManager.ping_groq("")) == (False, "Missing Key")

    def test_bad_format_no_network(self, monkeypatch):
        # must not even attempt a request for a wrong-format key
        def boom(*a, **k):
            raise AssertionError("should not open a session for a bad-format key")
        monkeypatch.setattr(utils.aiohttp, "ClientSession", boom)
        assert asyncio.run(utils.ConnectionManager.ping_groq("nope")) == (False, "Invalid Format")

    def test_connected_on_200(self, monkeypatch):
        monkeypatch.setattr(utils.aiohttp, "ClientSession", lambda *a, **k: _FakeSession(200))
        assert asyncio.run(utils.ConnectionManager.ping_groq("gsk_valid")) == (True, "Connected")

    def test_invalid_key_on_401(self, monkeypatch):
        monkeypatch.setattr(utils.aiohttp, "ClientSession", lambda *a, **k: _FakeSession(401))
        assert asyncio.run(utils.ConnectionManager.ping_groq("gsk_bad")) == (False, "Invalid Key")

    def test_unreachable_on_500(self, monkeypatch):
        monkeypatch.setattr(utils.aiohttp, "ClientSession", lambda *a, **k: _FakeSession(500))
        ok, msg = asyncio.run(utils.ConnectionManager.ping_groq("gsk_x"))
        assert ok is False and "Unreachable" in msg

    def test_unreachable_on_network_error(self, monkeypatch):
        def boom(*a, **k):
            raise OSError("network down")
        monkeypatch.setattr(utils.aiohttp, "ClientSession", boom)
        assert asyncio.run(utils.ConnectionManager.ping_groq("gsk_x")) == (False, "Unreachable")


class _PostResp:
    def __init__(self, status, payload=None, headers=None):
        self.status = status
        self._payload = payload or {}
        self.headers = headers or {}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def json(self):
        return self._payload


def _seq_session_factory(statuses):
    """Returns a ClientSession factory whose successive .post() calls yield the
    given HTTP statuses (a 200 carries a valid chat-completion payload)."""
    state = {"i": 0}

    class _S:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        def post(self, *a, **k):
            i = state["i"]
            state["i"] += 1
            st = statuses[min(i, len(statuses) - 1)]
            payload = {"choices": [{"message": {"content": "OK"}}]} if st == 200 else {}
            return _PostResp(st, payload)

    return lambda *a, **k: _S()


async def _noop_sleep(*a, **k):
    return None


@pytest.mark.real_groq  # exercises the real query_groq_api against a mocked aiohttp
class TestQueryGroqRetry:
    def test_retries_then_succeeds_on_429(self, monkeypatch):
        monkeypatch.setattr(utils.aiohttp, "ClientSession", _seq_session_factory([429, 429, 200]))
        monkeypatch.setattr(utils.asyncio, "sleep", _noop_sleep)  # don't actually wait
        assert asyncio.run(utils.query_groq_api("gsk_x", "p")) == "OK"

    def test_returns_none_when_rate_limited_throughout(self, monkeypatch):
        monkeypatch.setattr(utils.aiohttp, "ClientSession", _seq_session_factory([429] * 12))
        monkeypatch.setattr(utils.asyncio, "sleep", _noop_sleep)
        assert asyncio.run(utils.query_groq_api("gsk_x", "p")) is None

    def test_missing_key_short_circuits(self):
        assert asyncio.run(utils.query_groq_api("", "p")) == "Error: Missing API Key"

    def test_batch_prompt_fits_the_small_fallback_model(self, monkeypatch, tmp_path):
        """Regression for Groq HTTP 413 (payload too large): when the 70b model is
        rate-limited, the batch prompt must still fit llama-3.1-8b-instant — so
        chunks stay <=6 items and per-item content is truncated."""
        import datetime
        import json
        import re as _re
        captured = []

        async def _fake(key, prompt, **kw):
            captured.append(prompt)
            ids = [int(m) for m in _re.findall(r"ID:(\d+)", prompt)]
            return json.dumps({"items": [
                {"id": i, "title": "כותרת", "summary": "• **תמונת מצב**: אירוע אבטחה ממשי."}
                for i in ids]})

        monkeypatch.setattr(utils, "query_groq_api", _fake)
        monkeypatch.setattr(utils.asyncio, "sleep", _noop_sleep)  # skip inter-chunk throttle
        monkeypatch.chdir(tmp_path)
        utils.init_db()
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        items = [{"title": f"unique{i} tokens{i} story{i}", "url": f"https://b/{i}", "date": now,
                  "source": "BleepingComputer", "summary": "long content " * 300}  # ~3900 chars each
                 for i in range(12)]
        out = asyncio.run(utils.AIBatchProcessor("k").analyze_batch(items))
        assert len(out) == 12
        assert captured, "AI path was not exercised"
        for p in captured:
            assert len(_re.findall(r"ID:\d+", p)) <= 6, "chunk larger than 6 items"
            assert len(p) < 9000, f"batch prompt too large for the 8b fallback: {len(p)} chars"

    def test_huge_retry_after_is_capped(self, monkeypatch):
        """Regression: a 429 with a huge Retry-After (daily-quota exhaustion) must
        NOT be honored verbatim — that hung the boot for an hour. Every backoff
        must stay capped and the call must give up quickly."""
        slept = []

        async def _capture_sleep(d, *a, **k):
            slept.append(d)

        class _Resp429:
            status = 429
            headers = {"retry-after": "3600"}

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def json(self):
                return {}

        class _Sess:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            def post(self, *a, **k):
                return _Resp429()

        monkeypatch.setattr(utils.aiohttp, "ClientSession", lambda *a, **k: _Sess())
        monkeypatch.setattr(utils.asyncio, "sleep", _capture_sleep)
        out = asyncio.run(utils.query_groq_api("gsk_x", "p"))
        assert out is None
        assert slept, "expected at least one backoff sleep"
        assert max(slept) <= 5, f"Retry-After was not capped — slept {slept}"
