# 🛡️ CTI War Room

An operational **Cyber Threat Intelligence** dashboard: it aggregates security
feeds, summarizes them into operational Hebrew with an LLM, and gives the analyst
live IOC investigation tools — all in a single Streamlit app.

> The UI is **Hebrew (RTL)**. This README is in English for reach; screenshots
> show the live Hebrew interface.

![Python](https://img.shields.io/badge/python-3.12-blue)
![Streamlit](https://img.shields.io/badge/streamlit-1.58-red)
![License](https://img.shields.io/badge/license-MIT-green)

## Features

- **🔴 Live feed** — pulls RSS / JSON / Telegram from 7 sources, de-duplicates,
  and summarizes each item into operational Hebrew with **Groq (Llama 3.3 70B)**.
  Stored in SQLite with a strict 7-day window.
- **🗂️ Threat-actor dossiers** — profiles of Iran-nexus APT groups plus an
  on-demand DuckDuckGo "deep web" sweep per actor.
- **🛠️ Investigation lab** — an analyst toolkit and a live **IOC lookup** across
  VirusTotal / urlscan.io / AbuseIPDB with an AI verdict.
- **🌍 Attack map** — the embedded Check Point live threat map.
- **Source health** — every sync reports which feeds succeeded or failed
  (no silent failures).

## Screenshots

> _Add screenshots under `docs/img/` and embed them here._

## Architecture

```
sources ──async fetch (CTICollector)──▶ LLM summarize/dedup (AIBatchProcessor, Groq)
        ──▶ SQLite (cti_dashboard.db, 7-day) ──▶ Streamlit UI (4 tabs)
```

Full details in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### Data sources

| Source | Type | Notes |
|---|---|---|
| BleepingComputer | RSS | general security news |
| The Hacker News | RSS | general security news |
| Unit 42 (Palo Alto) | RSS | research |
| CISA KEV | JSON | known-exploited vulnerabilities |
| INCD (gov.il) | RSS | Israel National Cyber Directorate |
| Israel_Cyber | Telegram | INCD alerts mirror |
| Malwarebytes | RSS | research |

## Setup

Requires **Python 3.11+** (developed and pinned on 3.12).

```powershell
git clone https://github.com/lidorAvr/cti-war-room.git
cd cti-war-room
python -m venv .venv
.\.venv\Scripts\python -m pip install -r requirements.txt
```

### Configuration (API keys)

All keys are **optional** — the app boots without them and disables the matching
capability (shown in the sidebar). To enable AI + enrichment, copy the example
and fill in your keys:

```powershell
copy .streamlit\secrets.toml.example .streamlit\secrets.toml
```

| Key | Enables | Get it at |
|---|---|---|
| `groq_key` | AI summaries + IOC verdicts | https://console.groq.com |
| `vt_key` | VirusTotal IOC lookup | https://www.virustotal.com |
| `urlscan_key` | urlscan.io lookup | https://urlscan.io |
| `abuseipdb_key` | AbuseIPDB IP reputation | https://www.abuseipdb.com |

`.streamlit/secrets.toml` is git-ignored — **never commit real keys.**

## Run

```powershell
.\run.ps1
```

or directly:

```powershell
.\.venv\Scripts\python -m streamlit run app.py
```

## Tests

```powershell
.\.venv\Scripts\python -m pip install -r requirements-dev.txt
.\.venv\Scripts\python -m pytest
```

## Disclaimer

Defensive CTI tooling for authorized security and research use. It reads public
feeds and queries third-party reputation APIs — respect each provider's Terms of
Service and rate limits, and note that AI/enrichment calls consume **your** API
quotas. Provided "as is", without warranty (see [LICENSE](LICENSE)).

## License

[MIT](LICENSE) © 2026 Lidor Avrahamy
