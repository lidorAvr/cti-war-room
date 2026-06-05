# Architecture

CTI War Room is a single-process Streamlit app with two modules: `app.py` (UI)
and `utils.py` (engine). State lives in a local SQLite file.

## Data flow

```
                 ┌─────────────────────────────────────────────┐
   7 sources ───▶│ CTICollector.get_all_data()  (async, aiohttp)│
 (RSS/JSON/TG)   │   → returns (items, per-source status)       │
                 └───────────────┬─────────────────────────────┘
                                 ▼
                 ┌─────────────────────────────────────────────┐
                 │ AIBatchProcessor.analyze_batch()  (Groq)     │
                 │   dedup (SequenceMatcher) → Hebrew summary    │
                 │   → tag + severity (rule-based)               │
                 └───────────────┬─────────────────────────────┘
                                 ▼
                 ┌─────────────────────────────────────────────┐
                 │ SQLite  intel_reports  (cti_dashboard.db)    │
                 │   strict 7-day retention (HISTORY_DAYS)       │
                 └───────────────┬─────────────────────────────┘
                                 ▼
                        Streamlit UI (4 tabs)
```

## Modules

### `utils.py` (engine)
- `get_secret(key, default)` — safe `st.secrets` access (never crashes when no `secrets.toml`).
- `get_headers`, `parse_flexible_date`, `is_recent`, `identify_ioc_type` — helpers.
- `init_db`, `get_existing_data`, `save_reports` — SQLite persistence + dedup keys.
- `CTICollector` — async fetch of all sources; `fetch_item` returns a per-source
  status dict `{source, url, ok, items, error}`; `get_all_data` returns
  `(items, statuses)`.
- `AIBatchProcessor` — Groq calls (`llama-3.3-70b-versatile`, fallback
  `llama-3.1-8b-instant`), batch summarize/dedup to Hebrew, plus
  `analyze_single_ioc`; `_determine_tag_severity` is transparent rule-based
  tagging (not "the AI decided").
- `ThreatLookup` — VirusTotal / urlscan.io / AbuseIPDB clients.
- `DeepWebScanner` — DuckDuckGo sweep per actor.
- `APTSheetCollector`, `AnalystToolkit` — static dossiers / tool links.
- `log` — `cti_war_room` logger; all caught exceptions are logged (no silent swallowing).

### `app.py` (UI)
- Config + RTL Hebrew CSS, `get_feed_card_html` renderer.
- Boot: `init_db()` then an initial sync; auto-refresh every 15 min.
- Sidebar: AI status, sync/reset, **capability banner** (missing keys),
  **source-health panel** (last sync).
- Tabs: `עדכונים שוטפים` (feed) · `תיקי תקיפה` (actors) · `מעבדת חקירות`
  (toolkit + IOC) · `מפת תקיפות` (map).

## Storage

Single table `intel_reports` (url is UNIQUE; indexed on url + title). Regular
sources are pruned past `HISTORY_DAYS = 7`; `INCD` and `DeepWeb` rows are kept.

## Configuration

API keys via `st.secrets` (`.streamlit/secrets.toml`, git-ignored). All optional;
a missing key disables only its capability. See the README for the key table.

## Design principles

- **Fail loud, not silent** — caught errors are logged; source failures surface in the UI.
- **Transparent scoring** — tag/severity is rule-based and inspectable.
- **Tight retention** — a hard 7-day window keeps the feed operational, not an archive.
