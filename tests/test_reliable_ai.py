"""Reliable AI everywhere (Phase 5).

- get_secret() falls back to an environment variable so AI/enrichment work
  without a project secrets.toml (Claude_Preview, cron, deploy).
- ConnectionManager.ping_groq() is a REAL reachability check (the old check_groq
  only validated the key *format*).
"""
import asyncio
import os
import sys

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
