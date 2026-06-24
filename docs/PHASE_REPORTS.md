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

---

## Phase 1 — Reliability Hardening  ✅ PASS

| | |
|---|---|
| **Date** | 2026-06-05 |
| **Branch** | `phase-1-reliability` → PR to `main` |
| **Goal** | Close F1/F2/F3 — the tool must fail **loudly**, not silently. |

### Built
- **F1 — no-secrets crash fixed.** New `get_secret()` in `utils.py` wraps `st.secrets` so a missing key *or* a missing `secrets.toml` returns a default instead of raising `StreamlitSecretNotFoundError`. `app.py` uses it for all 4 keys. Sidebar **capability banner** lists which keys are missing (AI/enrichment disabled) instead of crashing.
- **F2 — EOL Gemini removed.** Dropped `import google.generativeai`, `polish_with_gemini`, and its 2 per-item calls (Groq already returns operational Hebrew). Removed `google-generativeai` from `requirements.txt` → venv slimmed **~85 → 67 packages** (no google-*/grpc/pydantic/cryptography).
- **F3 — no silent failures.** All **16 bare `except:`** replaced with scoped `except Exception` + a `cti_war_room` logger. `CTICollector.fetch_item`/`get_all_data` now return **per-source status**; sidebar **source-health panel** + honest `מקורות פעילים X/N` and `זמינות מקורות %` metrics (replaced the fake hard-coded "100%").

### Tested (gate)
- **`pytest` 36/36 green** on the slimmed 3.12.10 venv (+5 Phase 1 tests).
- **Live feeds smoke** on the refactored `get_all_data`: 78 items — and a **real `INCD` HTTP 403 was surfaced** (logged + in status), exactly the failure the old bare `except` hid.
- **Real `streamlit run` headless boot** clean (health 200, no traceback).
- Confirmed **no google/grpc/pydantic** packages remain.

### New tests (`tests/test_phase1.py`, 5)
`get_secret` default w/o file · **app boots WITHOUT secrets** (the original F1 crash, now a regression test) · Gemini layer removed · `get_all_data` returns items+statuses · sidebar surfaces a failed source.

### Not tested (deferred)
- Groq AI summary quality and IOC enrichment (need real API keys) — manual / later.
- Manual click-through UX — owner's call.

### Scope / behavior
- Behavior changes here are **intentional reliability fixes**: no crash on missing secrets, visible source failures, honest availability metrics, dead Gemini path removed.
- **F1, F2, F3 closed.**

**Gate: PASS.**

---

## Phase 2 — Documentation & Onboarding  ✅ PASS

| | |
|---|---|
| **Date** | 2026-06-05 |
| **Branch** | `phase-2-docs` → PR to `main` |
| **Goal** | Anyone (incl. future-you) can set up and run in ~5 minutes. |

### Built
- **`README.md`** (English, by owner choice): overview, features, architecture diagram, sources table, setup, run, secrets config table, tests, disclaimer, MIT badge.
- **`.streamlit/secrets.toml.example`** — documents the 4 active keys (`groq_key`, `vt_key`, `urlscan_key`, `abuseipdb_key`); all optional. (`gemini_key` dropped in Phase 1.)
- **`LICENSE`** — MIT © 2026 Lidor Avrahamy (owner choice).
- **`run.ps1`** — one-command launcher (ensures venv, installs deps, warns if no secrets, runs Streamlit).
- **`docs/ARCHITECTURE.md`** — data flow, modules, storage, design principles.

### Tested (gate)
- `secrets.toml.example` parses as valid TOML (keys: groq/vt/urlscan/abuseipdb).
- `run.ps1` **launches the app end-to-end** headless — health 200, Streamlit started.
- `pytest` **36/36** green (no code change).
- README / ARCHITECTURE render as Markdown.

### Decisions (owner)
- LICENSE = **MIT**; README language = **English**.

### Notes / follow-ups
- Streamlit binds all interfaces by default (`run.ps1` shows Network/External URLs) — bind address / exposure to be handled in **Phase 3 (deploy)**.
- Screenshots are a placeholder in the README (`docs/img/`) — to be added.

**Gate: PASS.**

---

## Phase 3 (CI) — Continuous Integration  ✅ PASS  ·  deploy deferred

| | |
|---|---|
| **Date** | 2026-06-05 |
| **Branch** | `phase-3-ci` → PR to `main` |
| **Goal** | Automated test gate on every push; **deploy intentionally deferred** (owner decision). |

### Built
- **`.github/workflows/ci.yml`** — on push to `main` + PRs to `main` (one run per change, no duplicates): checkout, Python 3.12, `pip install -r requirements-dev.txt`, `pytest`. pip cache enabled.
- **CI status badge** in `README.md`.

### Tested (gate)
- **GitHub Actions run `27015227656` = success in 52s** (checkout · setup 3.12 · install · pytest 36/36).

### Deploy — DEFERRED (owner)
Per owner: public deployment is **not** started. Open before Phase 3 deploy:
- **D2** target — Streamlit Community Cloud vs Docker self-host.
- Public-exposure + **API-cost** review (Groq/VT/URLScan/AbuseIPDB quotas), the auto-refresh hammering sources, the embedded iframe, and binding address.

### Notes / follow-ups
- GitHub flagged `actions/checkout@v4` + `actions/setup-python@v5` run on Node 20 (auto-forced to Node 24 ~2026-06-16) — bump action majors when convenient.

**Gate: PASS (CI green).**

---

## Phase 4a — Graceful no-AI feed fallback  ✅ PASS

| | |
|---|---|
| **Date** | 2026-06-05 |
| **Branch** | `feat-raw-feed-fallback` → PR to `main` |
| **Goal** | The feed must show real intel even with no Groq key (owner-found gap). |

### Problem
The app fetched real items successfully (6–7 sources, ~80/run) but the feed went
**blank without a Groq key** — items were discarded at the AI-summary step
(`save_reports` only stored AI-analyzed rows). The connection was real; only the
display depended on a paid/AI key.

### Built
- `AIBatchProcessor.analyze_batch`: the AI call now runs only `if self.key`, and
  **when a chunk yields no AI output (no key, Groq error, or unparseable JSON) the
  RAW fetched items are kept** — rule-based `_determine_tag_severity`, `category="Raw"`.
  With a key, behavior is unchanged (Hebrew AI summaries).
- `app.get_feed_card_html`: subtle **"גולמי · ללא AI"** badge on raw cards (transparency).

### Tested (gate)
- `pytest` **39/39** (+3: raw kept without key incl. rule-based High severity; empty input; no re-add of already-stored items).
- **Live end-to-end with NO key**: fetched **80** real items → **75 saved & shown** (deduped) — e.g. *"Cisco SD-WAN zero-day exploited in attacks"*, *"Everest Forms Pro WordPress flaw exploited"*, *"FIFA World Cup 2026 scams"*.

### Scope / behavior
- Graceful degradation only; the AI path is untouched when a key is present.
- Aligns with the project principle: always-working fallback (raw before AI), no silent blank screen.

**Gate: PASS.**

---

## Phase 4c — English UI (native LTR)  ✅ PASS

| | |
|---|---|
| **Date** | 2026-06-05 |
| **Branch** | `feat-english-ui` → PR to `main` |
| **Goal** | Comfortable, correctly-aligned UI. The forced global RTL broke Streamlit's layout. |

### Why
Streamlit is LTR-native; the previous global `direction: rtl; text-align: right` on
every element fought BaseWeb components and rendered poorly. Owner chose a clean
**English LTR** UI over fragile RTL hacks.

### Built
- Removed the global RTL CSS → **native LTR layout** (Inter font; Heebo kept as Hebrew fallback).
- Translated **all UI chrome to English**: title, sidebar, Sync/Reset, tabs, metrics, capability banner, source-health panel, feed filters, IOC lab, toolkit, statuses, empty states, footer.
- English tags (`Israel / Vulnerabilities / Phishing / Malware / Research / General`) and English APT dossiers.
- Feed cards use **`dir="auto"`**: Hebrew AI summaries render RTL, English raw items render LTR — automatically, inside the LTR UI.
- **AI summaries + IOC analysis stay Hebrew** (owner choice); the Groq prompts are unchanged.

### Tested (gate)
- `pytest` **39/39** (updated tag-severity and title assertions to English).
- **Live**: English tabs/metrics confirmed (Reports/Critical alerts/Active sources/Source availability), 75 real items rendered, `dir="auto"` working.

**Gate: PASS.**

---

## Phase 4d — Source expansion (Israel + general)  ✅ PASS

| | |
|---|---|
| **Date** | 2026-06-05 |
| **Branch** | `feat-more-sources` → PR to `main` |
| **Goal** | More Israeli/Hebrew/INCD coverage + reliable general sources that actually work with the app. |

### Method
Tested ~25 candidate feeds against the app's real fetch logic and kept only those returning recent items and not blocked. (Verified-broken/blocked, NOT added: Geektime, Sophos, JPost 404, CISA advisories — Cloudflare 403, Times of Israel — too general.)

### Built
- **Robustness fix** — `_entry_summary()`: RSS entries lacking `summary` (e.g. **Dark Reading**) no longer crash the whole source; falls back to description/content, and `title`/`link` are read defensively (entries with no link are skipped).
- **+16 verified sources** (7 → 26 total):
  - 🇮🇱 **Israel/Hebrew**: People & Computers (pc.co.il), Cyber News IL (rss.app — *חדשות סייבר / ארז דסה*), CyberSafe, Techz (cyber tag), INCD Alerts (`CyberGovIL`).
  - 🔬 **Top-tier**: SANS ISC, Securelist, Talos, Check Point Research, ESET, Mandiant, Krebs, Schneier, DFIR Report, Project Zero.
  - 📰 **News**: SecurityWeek, Security Affairs, GBHackers, Dark Reading.

### Tested (gate)
- `pytest` **43/43** (+4: source registry well-formed & unique URLs; `_entry_summary` robustness).
- **Live smoke**: **221 items, 25/26 sources active** — Hebrew coverage now strong (People & Computers 30, Cyber News IL 25, INCD 4). Only `INCD` gov.il RSS fails (Cloudflare 403 — known, kept as honest indicator).

### Note
More sources → more items per sync. With a Groq key this means more AI calls (cost); without a key the no-AI fallback keeps it free.

**Gate: PASS.**

---

## Phase 4e — Feed quality & relevance  ✅ PASS

| | |
|---|---|
| **Date** | 2026-06-17 |
| **Branch** | `feat-feed-quality` → PR to `main` |
| **Goal** | Owner feedback: balance sources, shorter cards, drop ads/off-topic, surface all INCD, INCD = high. |

### Built
- **Per-source cap** (`cap_per_source`, `PER_SOURCE_CAP=10`): high-volume feeds (THN, P&C) no longer dominate the displayed feed.
- **Summary truncation** (350 chars) in feed cards — no more walls of text.
- **Noise filter** (`is_noise`): drops marketing/promo (`תוכן שיווקי`, sponsored…) from any source, and off-topic stories from general-tech sources (People & Computers) lacking a cyber keyword (funding rounds, robotaxi, appointments).
- **INCD → severity High** (national-CERT alerts are always high-priority).
- **Telegram (INCD)**: ingest **all** page messages (not just 7 days) **and give each post a distinct title** — fixes the real cause of "not all the newest INCD appear": every post shared the title "INCD Cyber Alert", so the title-similarity de-dup collapsed them all into one.
- **Bug fix (found by the live UI smoke)**: pandas 3.0 raised `ValueError: Mixed timezones` in `to_datetime` on real multi-source dates (Telegram UTC + RSS Israel time) → fixed with `utc=True`. The single-row unit test didn't catch it; real data did.

### Tested (gate)
- `pytest` **54/54** (+ `is_noise`, `cap_per_source`, title-dedup collapse, **mixed-timezone regression**).
- **Live smoke** (26 sources, no key): 96 cards, **max 10/source**, **INCD 10** (was 1), no marketing, no off-topic, no tz error.

**Gate: PASS.**

---

## Phase 4f — Cross-source de-dup & relevance  ✅ PASS

| | |
|---|---|
| **Date** | 2026-06-17 |
| **Branch** | `feat-dedup-relevance` → PR to `main` |
| **Goal** | Don't show the same story from multiple outlets; drop low-value "junk" while keeping SOC-relevant items. |

### Verified the problem first
Live fetch had **18 duplicate items / 6 cross-source clusters** — the same CVE/story from 3–4 outlets (e.g. CISA KEV + The Hacker News + Security Affairs on CVE-2026-20262) — that the old `SequenceMatcher(0.75)` title de-dup missed (each outlet phrases the title differently).

### Built
- **Cross-source de-dup**: normalized **title token-set Jaccard (≥0.5) + shared-CVE** matching (`_signature` / `is_duplicate`), replacing the raw-title SequenceMatcher. The richest copy (longest summary) is kept; terse duplicates dropped.
- **Low-value filter** (`is_low_value`): drops marketing / surveys / business-HR / podcasts — matched on the **title only, word-bounded**.
- **Hardened against false positives (both caught by the live smoke):** `"sponsored"` appears in The Hacker News *body* boilerplate, and `"ebook"` is a substring of *"Facebook"* — title-only + latin word-boundary matching fixed both, so real intel (NarwhalRAT, JDY botnet, Facebook scams, Dark Reading threat groups) is kept.

### Tested (gate)
- `pytest` **64/64** (+ marker word-boundary `ebook`⊄`Facebook`, `is_duplicate` CVE/token, `analyze_batch` collapses one CVE across 3 outlets, sponsored-in-body kept).
- **Live verify**: 238 fetched → 29 junk dropped (all genuine) → **195 unique** (14 cross-source dups removed); every duplicate CVE appears **once**; INCD 10. UI renders clean (122 capped cards, no error).

**Gate: PASS.**

---

## Hotfix — Feed-card rendering (AI cards shown as code blocks)  ✅ PASS

| | |
|---|---|
| **Date** | 2026-06-24 |
| **Branch** | `feat-card-render-fix` → PR to `main` |
| **Goal** | Owner-reported display bug: AI-summarized cards rendered as literal HTML inside a Markdown code block; bold shown as raw `**`; awkward `<br>` gaps. |

### Root cause (two issues, found by reading the owner's pasted feed)
- `get_feed_card_html` returned an **indented** multi-line f-string. For **AI** cards `raw_badge` is empty (`''`) → its line became **whitespace-only**, which Streamlit's Markdown reads as a blank line: it closes the HTML block, and the following 4-space-indented lines become an **indented code block**. RAW cards carry a non-empty badge line, so they never tripped it — exactly why *only* AI cards broke.
- Streamlit's Markdown does **not** process markdown inside an HTML block, so `**bold**` from the Groq summary rendered **literally**.

### Built
- Convert `**x**` → `<strong>x</strong>` (and drop any dangling `**` left by truncation).
- Collapse newlines + whitespace-only runs to a single `<br>` (kills the `<br>     <br>` gaps the model emits).
- **Return the card HTML as one un-indented line** (`"".join(strip per line)`) so Markdown can never treat it as a code block.
- Sanitize the title (no embedded newline that could split the single line).

### Tested (gate)
- `pytest` **68/68** (+ `tests/test_card_render.py`: AI card is single-line / not a code block, `**`→`<strong>`, no literal `**`, `<br>`-gap collapse, RAW card still renders + keeps its badge).
- Fixed a **pre-existing latent test** (`test_app_renders_feed_with_mixed_timezones`): its hardcoded `2026-06-15` dates fell outside `init_db()`'s 7-day retention prune once the calendar passed the window → now anchored to `now` (still mixed offsets). *Not caused by this change — surfaced by it.*
- **Live UI verify** (Claude_Preview, real DOM): seeded a Hebrew AI card (`**` + messy `\n   \n`) into the running app → renders as a `.report-card` with three `<strong>` labels, **0 `<pre>/<code>` blocks across 125 cards**, no `**` leak, no ugly `<br>` gap.

**Gate: PASS.**

---

## Hotfix — Empty AI summaries → raw fallback  ✅ PASS

| | |
|---|---|
| **Date** | 2026-06-24 |
| **Branch** | `feat-empty-summary-fallback` → PR to `main` |
| **Goal** | Owner-reported: some cards showed the AI bullet template with **every section empty** (e.g. FortiBleed, Xsolis) — no usable intel. |

### Root cause
Groq occasionally returns the JSON item with the bullet scaffolding but **no content** (`• **תמונת מצב**: <br>• **ממצאים טכניים**: <br>• **משמעויות**:`). `analyze_batch` accepted any non-null `summary` as a finished AI ("News") item, so empty bullets reached the feed.

### Built
- `_is_empty_ai_summary()` — detects scaffolding-only output (strips `<br>`, the `**bold**` section labels, and non-alphanumerics; < 8 real chars ⇒ empty).
- **Per-item fallback** in `analyze_batch`: an empty AI summary now degrades *that item* to a **RAW card showing the original source text** (rule-based tag/severity), exactly like the no-key path — instead of empty bullets.
- Refactored the chunk-level raw fallback into a shared `_raw_result()` (no behaviour change).

### Tested (gate)
- `pytest` **75/75** (+ `tests/test_empty_summary.py`: helper unit cases; `analyze_batch` empty-template → Raw with the source text preserved; real-AI → News; **end-to-end through app.py**: boot → perform_update → analyze_batch(empty) → save → feed shows the source text and the template never reaches the UI).
- **Live UI verify** (Claude_Preview, real DOM): ran the real pipeline (`analyze_batch` + `save_reports`) against the live DB with Groq stubbed to return the empty template → the card renders as **RAW · no AI with the full source text**, no empty `תמונת מצב` bullets, 0 code blocks.

**Gate: PASS.**

---

## Phase 5 — Reliable AI everywhere (honest status + CWD-independent keys)  ✅ PASS

| | |
|---|---|
| **Date** | 2026-06-24 |
| **Branch** | `feat-reliable-ai` → PR to `main` |
| **Goal** | Owner: "AI not active — make it reliable everywhere." Find why AI looked off and make AI provisioning + status truthful across environments. |

### Root cause (found by live inspection)
1. **No key is configured** — every key in `.streamlit/secrets.toml` is **empty** (`groq_key=""`). That is the real reason AI was off; the Hebrew summaries the owner saw earlier came from a past run whose AI rows persist in the DB.
2. **Claude_Preview** launched the app from `C:\Users\lidor` (launch.json had no `cwd`) → Streamlit looked for secrets/DB in the wrong place.
3. **Dishonest status** — the old `check_groq` only checked the key *format* (`gsk_` prefix) and reported "Connected" without ever contacting Groq.

### Built
- **CWD-independent secrets**: `get_secret()` now falls back to an **environment variable** (`groq_key` → `GROQ_KEY`) after `st.secrets`, so AI/enrichment work without a project `secrets.toml` (preview, cron, deploy). `import os` added.
- **Real connectivity check**: `ConnectionManager.ping_groq()` hits Groq's free `/models` endpoint (no token cost) → honest status **Connected / Invalid Key / Unreachable / Missing Key**, run once per boot/sync and cached in `session_state['ai_status']` (not per rerun). `check_groq` kept as the instant pre-ping format check ("Configured").
- **Preview fix**: added `cwd` to `launch.json` so Claude_Preview runs from the project dir (uses the same `secrets.toml` + DB as `run.ps1`). *(launch.json is user-level config, not in the repo.)*
- **Docs**: `secrets.toml.example` documents the env-var alternative and the honest status values.

### Tested (gate)
- `pytest` **84/84** (+ `tests/test_reliable_ai.py`: `get_secret` env fallback + default; `ping_groq` → Connected/Invalid Key/Invalid Format/Missing Key/Unreachable, all with a mocked session).
- **Live verify**: `cwd` confirmed working (preview now writes/reads the **project** DB); `get_secret` env fallback confirmed live (`demo_key_x → env-value-xyz`); the real ping ran inside the live app and **correctly reported "Missing Key"** (because the key is empty). A live "Connected" awaits the owner setting a valid `gsk_` key.

**Gate: PASS** (code + tests + honest-status pipeline verified live; full AI activation is owner-action: set a Groq key).

---

## Phase 6 — Feed uniformity & AI reliability  ✅ PASS

| | |
|---|---|
| **Date** | 2026-06-24 |
| **Branch** | `feat-ai-prompt-quality` → PR to `main` |
| **Goal** | Owner (AI now keyed): "items aren't uniform — some Hebrew, some English; structure inconsistent; not enough context per item." |

### Root causes (found live with a real key)
- The mix is RAW (English, unstructured) vs AI (Hebrew, structured). Most RAW items came from **rate-limit (429) burst failures** during ingest — the old `query_groq_api` only did `time.sleep(1)` and skipped to the next model, so whole chunks degraded to RAW (a fresh-DB ingest produced ~72 AI / ~110 RAW).
- The AI prompt was thin: 3 sections, keyword-only "ממצאים טכניים", a literal `Impact` placeholder, no recommendations.
- A fresh/empty DB tried to AI-summarize the **entire backlog (~220+) on boot**, hanging the UI for many minutes on free-tier limits.

### Built
- **Richer, uniform prompt** (`utils.analyze_batch`): a fixed **4-section** Hebrew brief — `תמונת מצב / ממצאים טכניים / המלצות הגנה / רלוונטיות ל-SOC` — with explicit rules that every section carry a real sentence (no keyword lists, no empty sections, name victim/attacker/vector/CVE).
- **429 retry with short exponential backoff** + honoring `Retry-After`, before falling back to the smaller model — so rate-limited chunks recover instead of silently going RAW. Backoff is short so an exhausted quota fails fast to RAW rather than hanging.
- **Inter-chunk throttle** (2s) to avoid tripping free-tier limits in a burst.
- **Per-run cap** (`MAX_AI_ITEMS_PER_RUN = 40`, newest first) so a large/empty-DB backlog can't hang the boot; the rest fill in on the next sync / 15-min auto-refresh.
- **Per-category card width**: AI cards get more room (600 chars) for the richer summary; RAW stays tight (300) so it isn't a wall of text. Stray model indentation is normalized before truncation.

### Tested (gate)
- `pytest` **90/90** (+ `tests/test_reliable_ai.py` query_groq retry matrix: 429→retry→200, all-429→None, missing-key; + `tests/test_card_render.py` AI-vs-RAW truncation caps; + `tests/test_empty_summary.py` per-run cap = 40 of 50).
- **Live verify (real key):** the 4-section Hebrew format renders in the real DOM (rich, uniform, `המלצות הגנה` + `רלוונטיות ל-SOC`, 0 code blocks); the per-run cap is confirmed live (boot shows **"Analyzing 40"**, not the full ~227). AI/RAW ratio depends on live Groq free-tier headroom; the retry/throttle raise AI coverage when the quota has room.

### Notes / known limits
- The prompt lives in **code** (`utils.py`), shipped via GitHub — there is nothing to "configure" on Streamlit Cloud for the format; Cloud picks it up on redeploy from `main`.
- On free-tier Groq + an empty DB, a cold-start ingest is bounded (≤40/run) but can still be slow when the quota is exhausted; coverage backfills over subsequent syncs. A paid Groq tier or a persistent DB removes this.

**Gate: PASS** (code + 90 tests; format & cap verified live; full-backlog coverage rate is free-tier-bound).
