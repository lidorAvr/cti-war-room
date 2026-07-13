"""Shared test hygiene.

Every AppTest boot runs perform_update, which (since Phase 8) also pulls the
dedicated IOC feeds — multi-MB live downloads. Tests must stay hermetic, so the
fetch is stubbed to a no-op by default; tests that exercise the feed logic
itself opt out with @pytest.mark.real_ioc_feeds (and mock aiohttp instead).
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils  # noqa: E402


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "real_ioc_feeds: do not stub utils.fetch_ioc_feeds (test mocks the network itself)")
    config.addinivalue_line(
        "markers", "real_groq: do not stub the Groq call/ping functions (test mocks aiohttp itself)")


@pytest.fixture(autouse=True)
def _hermetic_ioc_feeds(request, monkeypatch):
    if request.node.get_closest_marker("real_ioc_feeds"):
        yield
        return

    async def _no_feeds(*a, **k):
        return []

    monkeypatch.setattr(utils, "fetch_ioc_feeds", _no_feeds)
    yield


@pytest.fixture(autouse=True)
def _hermetic_groq(request, monkeypatch):
    """Tests must NEVER reach the real Groq API (it burns the owner's quota and
    makes results nondeterministic). This bit us for real: AppTest sometimes
    merges the project's actual .streamlit/secrets.toml over the test-injected
    empty secrets (secrets file-watcher race), so an unstubbed test hit live
    Groq intermittently — the TestIncdPriorityInCap flake. Tests that exercise
    the real functions against a mocked aiohttp use @pytest.mark.real_groq;
    tests that install their own fake via monkeypatch simply override this stub."""
    if request.node.get_closest_marker("real_groq"):
        yield
        return

    async def _no_groq(*a, **k):
        return None

    async def _no_ping(*a, **k):
        return (False, "Missing Key")

    monkeypatch.setattr(utils, "query_groq_api", _no_groq)
    monkeypatch.setattr(utils.ConnectionManager, "ping_groq", staticmethod(_no_ping))
    yield
