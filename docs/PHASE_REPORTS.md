# CTI War Room — Phase Reports

Verification log, one section per phase. Gate per phase: `pytest` green + real-UI
smoke + this report, no open critical finding. Roadmap: see
`C:\Users\lidor\.claude\plans\cti-war-room-roadmap.md`.

---

## Phase 0 — Safety Net & Repo Hygiene  ✅ PASS

| | |
|---|---|
| **Date** | 2026-06-05 |
| **Branch** | `phase-0-safety-net` → PR to `main` |
| **Goal** | Lock current behavior & make builds reproducible BEFORE any refactor. No app behavior change. |

### Built
- **Python 3.12.10** standalone (per-user) installed; `.venv` rebuilt on it (was 3.9.13, EOL — D3).
- **`.gitignore`** — protects `.streamlit/secrets.toml`, `*.db`, `.venv/`, `__pycache__/`, logs.
- **`requirements.txt`** pinned to versions verified on 3.12.10 (reproducible builds).
- **`requirements-dev.txt`** — `-r requirements.txt` + `pytest>=8,<9`.
- **`pytest.ini`** — `pythonpath=.`, `testpaths=tests`.
- **`tests/`** (31 tests):
  - `test_pure_functions.py` (27) — characterization of `identify_ioc_type`, `is_recent`, `parse_flexible_date`, `AIBatchProcessor._determine_tag_severity`, `is_similar`.
  - `test_app_boot.py` (4) — real Streamlit `AppTest` boot: no exception, 4 tabs, ops title, **feed renders with seeded data** (pandas-3.x guard).
- **git** — local identity (`lidorAvr` / `lidoravr@github.com`), branch `phase-0-safety-net` (D4).

### Tested (gate)
- **`pytest` 31/31 green** on Python 3.12.10.
- **Real `streamlit run` headless boot** — health endpoint 200 in ~1.5s, Uvicorn up, **no traceback** in logs.
- **Feed network smoke** (baseline) — 80 items / 7 days across 6 sources (TheHackerNews 41, BleepingComputer 15, Malwarebytes 14, CISA/KEV 4, INCD 4, Unit 42 2).

### Failed + fixed
- **winget hung ~10 min on UAC** (py-launcher all-users install needs admin) → switched to **python.org per-user silent** install (`InstallAllUsers=0 Include_launcher=0`) → clean, no admin.
- **3.12.11–3.12.13 are source-only** (no Windows installer) → used **3.12.10** (last 3.12 with an `amd64.exe`).
- **Test bug** — `assert at.exception is None` always fails (`at.exception` is an `ElementList`, never `None`) → fixed to `len(at.exception) == 0`. (Caught by validating tests early on the 3.9 venv.)
- **Version drift on 3.12** — unpinned install resolved **pandas 3.0.3** and **streamlit 1.58.0** (major bumps) → added the feed-data-render test to de-risk pandas 3.x → green → pinned the verified set.

### Not tested (deferred)
- **AI analysis (Groq)** and **IOC enrichment (VT/URLScan/AbuseIPDB)** — require API keys; will be exercised in Phase 1 manual smoke.
- pandas data paths beyond the single seeded feed row.
- **Manual click-through UX acceptance** — owner's call (`streamlit run app.py`).

### Scope / behavior
- **No change to `app.py` / `utils.py` logic.** Only added tooling, tests, pins, and the env migration.
- Known findings **intentionally deferred to Phase 1**: F1 (no-`secrets.toml` boot crash), F2 (google-generativeai EOL), F3 (16 bare `except:`).

**Gate: PASS — no open critical finding for Phase 0 scope.**
