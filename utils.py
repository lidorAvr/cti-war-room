import sqlite3
import os
import asyncio
import aiohttp
import json
import datetime
import requests
import pandas as pd
import re
import ipaddress
import pytz
import feedparser
import base64
import time
import logging
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from dateutil import parser as date_parser
from duckduckgo_search import DDGS
import streamlit as st
from difflib import SequenceMatcher
from fake_useragent import UserAgent

DB_NAME = "cti_dashboard.db"
IL_TZ = pytz.timezone('Asia/Jerusalem')

# --- CONFIGURATION ---
HISTORY_DAYS = 7    # טווח קשיח: שבוע אחרון בלבד
FETCH_LIMIT = 100   # מקסימום שאיבה מכל מקור

log = logging.getLogger("cti_war_room")


def get_secret(key, default=""):
    """Safe access to a secret that never raises when no secrets.toml exists.

    Resolution order: st.secrets -> environment variable (KEY upper-cased, e.g.
    groq_key -> GROQ_KEY) -> default. The env-var fallback makes the app's
    capabilities (AI, IOC enrichment) work in environments WITHOUT a project
    secrets.toml — Claude_Preview (which runs from a different CWD), cron jobs and
    cloud deploys — instead of silently degrading to no-AI.

    st.secrets.get(key, default) raises StreamlitSecretNotFoundError when there is
    no secrets file at all (the supplied default is never reached), so it is wrapped.
    """
    try:
        val = st.secrets.get(key, None)
        if val:
            return val
    except Exception:
        pass
    return os.environ.get(key.upper(), default)


# --- ROBUST HEADERS ---
def get_headers():
    try:
        ua = UserAgent()
        return {'User-Agent': ua.random, 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}
    except Exception as e:
        log.debug("fake-useragent unavailable, using static UA: %s", e)
        return {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}


def _entry_summary(entry):
    """Robustly extract an RSS entry's summary text. Some feeds (e.g. Dark
    Reading) omit `summary`; fall back to description/content so one feed's
    quirk never crashes the whole source."""
    raw = getattr(entry, 'summary', None) or getattr(entry, 'description', None)
    if not raw:
        content = getattr(entry, 'content', None)
        if content:
            try:
                first = content[0]
                raw = first.get('value') if hasattr(first, 'get') else getattr(first, 'value', None)
            except Exception:
                raw = None
    return BeautifulSoup(raw or "", "html.parser").get_text()[:2500]


# --- Feed quality: drop marketing/promo and off-topic items ---
# General tech/business outlets (not cyber-only): for these we require a
# cyber/threat keyword, so funding rounds / appointments / gadgets are dropped
# while real security stories pass. Dedicated CTI sources are trusted as-is.
GENERAL_SOURCES = {"People & Computers"}

MARKETING_MARKERS = (
    "תוכן שיווקי", "תוכן ממומן", "פרסום ממומן", "מעוניינים לפרסם", "לפרסום בערוץ",
    "לפרסום אצלנו", "sponsored", "advertorial", "promoted post",
)

CYBER_KEYWORDS = (
    "cyber", "hack", "attack", "malware", "ransomware", "phish", "vulnerab",
    "exploit", "breach", "threat", "cve-", "apt", "ddos", "botnet", "backdoor",
    "trojan", "zero-day", "zero day", "0day", "spyware", "stealer", "incident",
    "compromise", "data leak", "leaked", "patch", "security",
    "סייבר", "פריצה", "מתקפ", "תקיפ", "נוזק", "כופר", "פישינג", "פגיעות",
    "דליפ", "דלף", "האקר", "תוקף", "חדיר", "אבטח", "פוגען", "סחיטה", "הצפנ",
)


def _title_has_marker(title, markers):
    """Word-bounded marker match on a title (lowercased). The latin-letter
    boundaries prevent substring false-positives like 'ebook' in 'Facebook' or
    'appointed' in 'disappointed'. Hebrew markers match within Hebrew text."""
    t = (title or "").lower()
    return any(re.search(r'(?<![a-z0-9])' + re.escape(m) + r'(?![a-z0-9])', t) for m in markers)


def is_noise(item):
    """Drop marketing/promo or low-value fluff (matched on the TITLE, so a real
    story isn't dropped for boilerplate like a 'sponsored' related-links footer in
    its body), or an off-topic story from a general-tech source (no cyber keyword)."""
    if _title_has_marker(item.get('title', ''), MARKETING_MARKERS):
        return True
    if is_low_value(item):
        return True
    text = f"{item.get('title', '')} {item.get('summary', '')}".lower()
    if item.get("source") in GENERAL_SOURCES and not any(k in text for k in CYBER_KEYWORDS):
        return True
    return False


def cap_per_source(df, n, source_col="source"):
    """Keep at most n rows per source (df assumed already sorted by recency) so
    high-volume feeds don't crowd out everyone else. Original order is preserved."""
    if df is None or df.empty:
        return df
    return df.groupby(source_col, group_keys=False, sort=False).head(n)


# --- Low-value / "junk" filter: items that aren't actionable for a SOC/CTI team ---
LOW_VALUE_MARKERS = (
    # vendor marketing / events / fluff
    "webinar", "register now", "register today", "whitepaper", "white paper",
    "e-book", "ebook", "download the report", "download our", "join us at",
    "podcast", "webcast", "stormcast", "lock and code", "virtual event", "promo code", "giveaway",
    "magic quadrant", "forrester wave", "gartner", "named a leader",
    # surveys / statistics fluff
    "survey", "respondents", "% of organizations", "% of companies",
    "% of security", "% of it leaders",
    # business / HR — not threat intel
    "raises $", "raises €", "series a funding", "series b funding",
    "funding round", "secures $", "acquires", "acquisition of", "to acquire",
    "appoints", "appointed", "names new ceo", "joins as", "we're hiring", "now hiring",
    # hebrew
    "וובינר", "הירשמו", "להרשמה", "סקר", "המשיבים", "גייסה", "גיוס הון",
    "סבב גיוס", "רכשה את", "מונה ל", "מינוי", "דרושים", "פודקאסט", "חסות",
)


def is_low_value(item):
    """True for clearly low-value items (marketing, surveys, business/HR, podcasts)
    not actionable for a SOC team. Matched on the TITLE only (word-bounded): a real
    threat story often cites a statistic or webinar in its body — don't drop it for that."""
    return _title_has_marker(item.get('title', ''), LOW_VALUE_MARKERS)


# --- Cross-source de-duplication (the same story from multiple outlets) ---
# SequenceMatcher on raw titles misses cross-outlet dups (each outlet phrases it
# differently). Compare normalized title token sets (Jaccard) and shared CVE ids.
_DEDUP_STOP = set((
    "the a an of to in on for and or with from is are was were be been by at as it "
    "its this that new now over into via after before amid update updates reports report "
    "says will has have can your you our flaw flaws bug warns warning alert vulnerability"
).split())


def _norm_tokens(text):
    t = re.sub(r'[^a-z0-9֐-׿ ]', ' ', (text or '').lower())
    return set(w for w in t.split() if len(w) > 2 and w not in _DEDUP_STOP)


def _cve_ids(text):
    return set(re.findall(r'cve-\d{4}-\d{4,7}', (text or '').lower()))


def _signature(item):
    blob = f"{item.get('title', '')} {item.get('summary', '')}"
    return (_norm_tokens(item.get('title', '')), _cve_ids(blob))


def is_duplicate(sig_a, sig_b, threshold=0.5):
    """Same story if the items share a CVE id or their title token sets overlap
    enough (Jaccard >= threshold)."""
    toks_a, cve_a = sig_a
    toks_b, cve_b = sig_b
    if cve_a and cve_b and (cve_a & cve_b):
        return True
    if not toks_a or not toks_b:
        return False
    return len(toks_a & toks_b) / len(toks_a | toks_b) >= threshold


def _is_empty_ai_summary(summary):
    """True when a Groq summary is just the bullet template with no real content,
    e.g. '• **תמונת מצב**: <br>• **ממצאים טכניים**: <br>• **משמעויות**:'. The model
    occasionally returns the scaffolding with every section blank; those items are
    better shown as their raw source text than as empty bullets."""
    if not summary or not summary.strip():
        return True
    t = summary.replace('<br>', ' ')
    t = re.sub(r'\*\*[^*]*\*\*', ' ', t)             # drop the **bold** section labels
    t = re.sub(r'[^0-9A-Za-z֐-׿]', '', t)  # keep only Hebrew/Latin letters + digits
    return len(t) < 8

# --- IOC EXTRACTION (deterministic, precision-first) ---
# IOC values are extracted ONLY from raw source text using regexes + validation —
# NEVER from AI output. An LLM can hallucinate an indicator, and these values may
# feed blocking rules, so the extraction path must be fully deterministic. Each
# IOC is stored with a link to its source report so an analyst can verify it.

# Publisher / ubiquitous-legit domains that must never appear in a blocking feed.
IOC_DOMAIN_DENYLIST = {
    # feed publishers (their own links appear inside article text)
    "bleepingcomputer.com", "thehackernews.com", "malwarebytes.com",
    "securityweek.com", "securityaffairs.com", "gbhackers.com", "darkreading.com",
    "paloaltonetworks.com", "unit42.paloaltonetworks.com", "isc.sans.edu",
    "securelist.com", "talosintelligence.com", "blog.talosintelligence.com",
    "checkpoint.com", "research.checkpoint.com", "welivesecurity.com",
    "mandiant.com", "krebsonsecurity.com", "schneier.com", "thedfirreport.com",
    "pc.co.il", "cybersafe.co.il", "techz.co.il", "geektime.co.il",
    "t.me", "telegram.org", "rss.app", "feedburner.com", "blogspot.com",
    "nvd.nist.gov", "cisa.gov", "gov.il",
    # giants / vendors routinely mentioned in articles
    "google.com", "microsoft.com", "apple.com", "github.com", "gitlab.com",
    "twitter.com", "x.com", "facebook.com", "meta.com", "youtube.com",
    "linkedin.com", "amazon.com", "aws.amazon.com", "cloudflare.com",
    "wikipedia.org", "fortinet.com", "cisco.com", "samsung.com", "oracle.com",
    "adobe.com", "vmware.com", "ibm.com", "intel.com", "whatsapp.com",
    "salesforce.com", "openai.com", "anthropic.com", "groq.com", "streamlit.io",
    "notion.so", "slack.com", "zoom.us", "dropbox.com", "npmjs.com", "pypi.org",
    # URL shorteners / social redirectors (article links leak these — never blockable)
    "t.co", "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "is.gd", "buff.ly",
    "lnkd.in", "youtu.be", "wa.me", "fb.me", "amzn.to", "redd.it", "rb.gy",
    "shorturl.at", "medium.com", "substack.com",
    # Israeli press (quoted inside Hebrew items)
    "ynet.co.il", "calcalist.co.il", "haaretz.co.il", "globes.co.il",
    "n12.co.il", "mako.co.il", "walla.co.il", "jpost.com", "timesofisrael.com",
}

# Conservative TLD allowlist — a "domain" match with an unlisted TLD is dropped
# (kills file names like report.pdf and code fragments like utils.py).
_IOC_TLDS = {
    "com", "net", "org", "info", "biz", "io", "co", "me", "cc", "ws", "su", "ru",
    "cn", "ir", "il", "in", "uk", "de", "fr", "nl", "br", "tr", "ua", "kr", "jp",
    "xyz", "top", "online", "site", "club", "vip", "shop", "app", "dev", "link",
    "click", "live", "pro", "store", "tech", "cloud", "one", "icu", "buzz",
    "cyou", "rest", "quest", "sbs", "lol", "zip", "today", "world", "life",
    "tk", "ml", "ga", "cf", "gq", "pw",
}

_ISRAEL_MARKERS = ("israel", "israeli", "ישראל", "ישראלי", "מערך הסייבר", "פיקוד העורף",
                   "idf", 'צה"ל', "iran", "iranian", "איראן")


def _refang(text):
    """Undo common defanging so regexes can match: hxxp->http, [.]/(.)/{.} -> '.',
    [:]->':', [at]->@. Applied to a COPY used for matching only."""
    t = text or ""
    t = re.sub(r'h[xX]{2}ps?', lambda m: m.group(0).lower().replace('xx', 'tt'), t)
    t = re.sub(r'[\[\({]\s*\.\s*[\]\)}]', '.', t)
    t = re.sub(r'\[\s*:\s*\]', ':', t)
    t = re.sub(r'\[\s*at\s*\]', '@', t, flags=re.I)
    return t


def _valid_public_ip(ip_str):
    # Trailing .0/.255 are rejected: product versions masquerade as IPs
    # (e.g. "Chrome 120.0.0.0") and network/broadcast addresses aren't C2s.
    if ip_str.endswith(('.0', '.255')):
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_global and not ip.is_multicast
    except ValueError:
        return False


def _domain_denied(domain):
    d = domain.lower()
    return any(d == deny or d.endswith("." + deny) for deny in IOC_DOMAIN_DENYLIST)


def extract_iocs(text):
    """Extract validated IOCs from RAW source text. Returns a list of
    {'value','type'} dicts, de-duplicated, in order of first appearance.
    Types: ip / domain / url / md5 / sha1 / sha256 / cve."""
    if not text:
        return []
    t = _refang(str(text))
    found, seen = [], set()

    def _add(value, ioc_type):
        key = (value.lower(), ioc_type)
        if key not in seen:
            seen.add(key)
            found.append({"value": value, "type": ioc_type})

    # CVEs (always safe to surface)
    for cve in re.findall(r'\bCVE-\d{4}-\d{4,7}\b', t, flags=re.I):
        _add(cve.upper(), "cve")

    # Hashes — strict hex with non-hex boundaries
    for h, typ in ((r'\b[a-fA-F0-9]{64}\b', "sha256"),
                   (r'\b[a-fA-F0-9]{40}\b', "sha1"),
                   (r'\b[a-fA-F0-9]{32}\b', "md5")):
        for m in re.findall(h, t):
            _add(m.lower(), typ)

    # URLs — keep only when the host itself is a valid indicator
    for m in re.findall(r'\bhttps?://[^\s<>"\'\)\]]+', t, flags=re.I):
        url = m.rstrip('.,;:!?')
        host = re.sub(r'^https?://', '', url, flags=re.I).split('/')[0].split(':')[0]
        if _valid_public_ip(host):
            _add(url, "url"); _add(host, "ip")
        elif '.' in host and host.rsplit('.', 1)[-1].lower() in _IOC_TLDS and not _domain_denied(host):
            _add(url, "url"); _add(host.lower(), "domain")

    # Bare IPv4s (regex already bounds octets to 0-255 via validation below)
    for m in re.findall(r'(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])', t):
        if _valid_public_ip(m):
            _add(m, "ip")

    # Bare domains — valid shape + allowlisted TLD + not denylisted
    for m in re.findall(
            r'\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,12})\b', t, flags=re.I):
        d = m.lower()
        if d.rsplit('.', 1)[-1] in _IOC_TLDS and not _domain_denied(d) and not _valid_public_ip(d):
            _add(d, "domain")

    return found


def is_israel_related(text, source, ioc_values=()):
    """Priority flag: item is (or may be) directly relevant to Israel."""
    if source in ("INCD", "INCD Alerts"):
        return True
    low = (text or "").lower()
    if any(mk in low for mk in _ISRAEL_MARKERS):
        return True
    return any(str(v).lower().rstrip('/').endswith('.il') or '.il/' in str(v).lower()
               for v in ioc_values)


def save_iocs(entries):
    """Persist extracted IOCs. entries: iterable of dicts with keys
    value/ioc_type/severity/tags/israel/source/report_url/report_title/first_seen."""
    if not entries:
        return 0
    conn = sqlite3.connect(DB_NAME)
    c, n = conn.cursor(), 0
    for e in entries:
        try:
            c.execute("""INSERT OR IGNORE INTO iocs
                (value, ioc_type, severity, tags, israel, source, report_url, report_title, first_seen)
                VALUES (?,?,?,?,?,?,?,?,?)""",
                (e["value"], e["ioc_type"], e.get("severity", "Medium"), e.get("tags", "General"),
                 1 if e.get("israel") else 0, e.get("source", ""), e.get("report_url", ""),
                 e.get("report_title", ""), e.get("first_seen", "")))
            if c.rowcount > 0:
                n += 1
        except Exception as ex:
            log.warning("failed to save IOC %s: %s", e.get("value"), ex)
    conn.commit()
    conn.close()
    return n


def extract_and_save_iocs(raw_items, analyzed):
    """Bridge the ingest pipeline into the IOC feed: extract from the RAW source
    text of each saved report (never from the AI summary) and persist, carrying
    the report's severity/tags plus an Israel-priority flag."""
    by_url = {r.get("url"): r for r in raw_items if r.get("url")}
    entries = []
    for a in analyzed:
        raw = by_url.get(a.get("url"))
        if not raw:
            continue
        src_text = f"{raw.get('title', '')}\n{raw.get('summary', '')}"
        iocs = extract_iocs(src_text)
        if not iocs:
            continue
        israel = is_israel_related(src_text, a.get("source", ""), [i["value"] for i in iocs])
        for i in iocs:
            entries.append({
                "value": i["value"], "ioc_type": i["type"],
                "severity": a.get("severity", "Medium"), "tags": a.get("tags", "General"),
                "israel": israel, "source": a.get("source", ""),
                "report_url": a.get("url", ""), "report_title": raw.get("title", ""),
                "first_seen": a.get("published_at", ""),
            })
    return save_iocs(entries)


def retag_reports():
    """Idempotent self-heal: recompute tag+severity for stored reports with the
    CURRENT bilingual keyword rules. Deterministic — rerunning yields the same
    result; DeepWeb rows (actor-scan hits) are left untouched."""
    try:
        proc = AIBatchProcessor("")
        conn = sqlite3.connect(DB_NAME)
        rows = conn.execute("SELECT id, source, title, summary, tags, severity FROM intel_reports "
                            "WHERE source != 'DeepWeb'").fetchall()
        updates = []
        for rid, source, title, summary, tags, severity in rows:
            tag, sev = proc._determine_tag_severity(f"{title} {summary}", source)
            if tag != tags or sev != severity:
                updates.append((tag, sev, rid))
        if updates:
            conn.executemany("UPDATE intel_reports SET tags = ?, severity = ? WHERE id = ?", updates)
            conn.commit()
            log.info("retagged %d report(s) with current rules", len(updates))
        conn.close()
    except Exception as e:
        log.debug("retag failed: %s", e)


def _purge_denied_iocs():
    """Remove stored domain/url IOCs whose host is (now) denylisted — keeps the
    blocking feed clean when the denylist is extended after ingestion."""
    try:
        conn = sqlite3.connect(DB_NAME)
        rows = conn.execute("SELECT id, value, ioc_type FROM iocs WHERE ioc_type IN ('domain','url')").fetchall()
        bad = []
        for rid, value, ioc_type in rows:
            host = re.sub(r'^https?://', '', str(value), flags=re.I).split('/')[0].split(':')[0]
            if _domain_denied(host):
                bad.append((rid,))
        if bad:
            conn.executemany("DELETE FROM iocs WHERE id = ?", bad)
            conn.commit()
            log.info("purged %d denylisted IOC(s)", len(bad))
        conn.close()
    except Exception as e:
        log.debug("ioc purge failed: %s", e)


def backfill_iocs():
    """One-off/idempotent: extract IOCs from already-stored RAW reports (their
    summary is the original source text). AI ('News') rows are skipped — their
    stored text is model output and must not feed the IOC list."""
    try:
        conn = sqlite3.connect(DB_NAME)
        rows = conn.execute(
            "SELECT source, url, title, summary, severity, tags, published_at "
            "FROM intel_reports WHERE category = 'Raw'").fetchall()
        conn.close()
        entries = []
        for source, url, title, summary, severity, tags, published_at in rows:
            src_text = f"{title}\n{summary}"
            iocs = extract_iocs(src_text)
            if not iocs:
                continue
            israel = is_israel_related(src_text, source, [i["value"] for i in iocs])
            for i in iocs:
                entries.append({"value": i["value"], "ioc_type": i["type"],
                                "severity": severity, "tags": tags, "israel": israel,
                                "source": source, "report_url": url, "report_title": title,
                                "first_seen": published_at})
        return save_iocs(entries)
    except Exception as e:
        log.warning("IOC backfill failed: %s", e)
        return 0

# --- DEDICATED IOC FEEDS (verified indicators, not news text) ---
# These feeds publish curated, already-verified indicators, so extraction is a
# straight parse — no LLM anywhere. The news-text TLD allowlist is deliberately
# NOT applied here (real C2s sit on exotic TLDs); the legit-domain denylist IS
# still enforced so a compromised-but-critical domain (github.com, a CDN…)
# can never reach the blocking feed. Endpoints verified live 2026-07-13:
# ThreatFox API needs an Auth-Key (401) but the public recent-export works.
MAX_FEED_IOCS = 40          # newest N per feed per fetch — keeps the tab focused
IOC_FEED_INTERVAL_MIN = 60  # fetch each feed at most hourly (they're multi-MB)

IOC_FEEDS = (
    {"name": "ThreatFox", "url": "https://threatfox.abuse.ch/export/json/recent/", "kind": "threatfox"},
    {"name": "URLhaus", "url": "https://urlhaus.abuse.ch/downloads/json_recent/", "kind": "urlhaus"},
    {"name": "OpenPhish", "url": "https://openphish.com/feed.txt", "kind": "openphish"},
)


def _feed_value_ok(value, ioc_type):
    """Safety gate for feed IOCs: denylist for domains/URL hosts, public-IP for
    ips, hex shape for hashes. No TLD allowlist (feeds are pre-verified)."""
    v = str(value or "").strip()
    if not v or len(v) > 500:
        return False
    if ioc_type == "ip":
        return _valid_public_ip(v)
    if ioc_type == "domain":
        return not _domain_denied(v)
    if ioc_type == "url":
        host = re.sub(r'^https?://', '', v, flags=re.I).split('/')[0].split(':')[0]
        if _valid_public_ip(host):
            return True
        return '.' in host and not _domain_denied(host)
    if ioc_type in ("md5", "sha1", "sha256"):
        return bool(re.fullmatch(r'[a-fA-F0-9]+', v))
    return True


def _parse_threatfox(data):
    """ThreatFox recent export: {ioc_id: [{ioc_value, ioc_type, threat_type,
    malware_printable, confidence_level, first_seen_utc, ...}]}."""
    out = []
    for ioc_id, entries in (data or {}).items():
        for e in entries or []:
            value = (e.get("ioc_value") or "").strip()
            t = e.get("ioc_type") or ""
            if t == "ip:port":
                value, ioc_type = value.split(":")[0], "ip"
            elif t in ("md5_hash", "sha256_hash", "sha1_hash"):
                ioc_type = t.split("_")[0]
            elif t in ("domain", "url"):
                ioc_type = t
            else:
                continue
            if not _feed_value_ok(value, ioc_type):
                continue
            conf = e.get("confidence_level") or 0
            malware = e.get("malware_printable") or e.get("malware") or "unknown"
            out.append({
                "value": value, "ioc_type": ioc_type,
                "severity": "High" if conf >= 75 else "Medium",
                "tags": "Malware",
                "israel": is_israel_related("", "", [value]),
                "source": "ThreatFox",
                "report_url": f"https://threatfox.abuse.ch/ioc/{ioc_id}/",
                "report_title": f"ThreatFox: {malware} ({e.get('threat_type', 'ioc')})",
                "first_seen": parse_flexible_date(e.get("first_seen_utc")),
                "_sort": e.get("first_seen_utc") or "",
            })
    out.sort(key=lambda x: x["_sort"], reverse=True)
    return out[:MAX_FEED_IOCS]


def _parse_urlhaus(data):
    """URLhaus json_recent: {id: [{url, url_status, threat, tags, urlhaus_link,
    dateadded, ...}]}."""
    out = []
    for _id, entries in (data or {}).items():
        for e in entries or []:
            url = (e.get("url") or "").strip()
            if not _feed_value_ok(url, "url"):
                continue
            tags = ",".join(e.get("tags") or []) or e.get("threat") or "malware"
            out.append({
                "value": url, "ioc_type": "url",
                "severity": "High" if e.get("url_status") == "online" else "Medium",
                "tags": "Malware",
                "israel": is_israel_related("", "", [url]),
                "source": "URLhaus",
                "report_url": e.get("urlhaus_link") or "https://urlhaus.abuse.ch/",
                "report_title": f"URLhaus: {e.get('threat', 'malware_download')} [{tags}]",
                "first_seen": parse_flexible_date(e.get("dateadded")),
                "_sort": e.get("dateadded") or "",
            })
    out.sort(key=lambda x: x["_sort"], reverse=True)
    return out[:MAX_FEED_IOCS]


def _parse_openphish(text):
    """OpenPhish free feed: newline-separated live phishing URLs (no metadata)."""
    out, now = [], datetime.datetime.now(IL_TZ).isoformat()
    for line in (text or "").splitlines():
        url = line.strip()
        if not url.lower().startswith(("http://", "https://")):
            continue
        if not _feed_value_ok(url, "url"):
            continue
        out.append({
            "value": url, "ioc_type": "url", "severity": "High", "tags": "Phishing",
            "israel": is_israel_related("", "", [url]), "source": "OpenPhish",
            "report_url": "https://openphish.com/", "report_title": "OpenPhish: active phishing URL",
            "first_seen": now,
        })
        if len(out) >= MAX_FEED_IOCS:
            break
    return out


def _ioc_feed_due(source):
    """Hourly gate per feed (they are multi-MB downloads)."""
    try:
        conn = sqlite3.connect(DB_NAME)
        row = conn.execute("SELECT last_fetch FROM ioc_feed_meta WHERE source = ?", (source,)).fetchone()
        conn.close()
        if not row or not row[0]:
            return True
        last = date_parser.parse(row[0])
        return (datetime.datetime.now(IL_TZ) - last).total_seconds() > IOC_FEED_INTERVAL_MIN * 60
    except Exception:
        return True


def _mark_ioc_feed_fetched(source):
    try:
        conn = sqlite3.connect(DB_NAME)
        conn.execute("INSERT OR REPLACE INTO ioc_feed_meta (source, last_fetch) VALUES (?, ?)",
                     (source, datetime.datetime.now(IL_TZ).isoformat()))
        conn.commit()
        conn.close()
    except Exception as e:
        log.debug("ioc feed meta update failed: %s", e)


async def fetch_ioc_feeds():
    """Fetch the dedicated IOC feeds (hourly-gated), parse, validate and persist.
    Returns per-feed status dicts for the sidebar; a feed failure never raises."""
    statuses = []
    for feed in IOC_FEEDS:
        name = feed["name"]
        if not _ioc_feed_due(name):
            continue  # fetched recently — nothing to report
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(feed["url"], headers=get_headers(), timeout=45) as resp:
                    if resp.status != 200:
                        statuses.append({"source": name, "ok": False, "count": 0,
                                         "error": f"HTTP {resp.status}"})
                        continue
                    if feed["kind"] == "openphish":
                        entries = _parse_openphish(await resp.text())
                    else:
                        data = await resp.json(content_type=None)
                        entries = _parse_threatfox(data) if feed["kind"] == "threatfox" else _parse_urlhaus(data)
            for e in entries:
                e.pop("_sort", None)
            added = save_iocs(entries)
            _mark_ioc_feed_fetched(name)
            statuses.append({"source": name, "ok": True, "count": added})
            log.info("IOC feed %s: %d parsed, %d new", name, len(entries), added)
        except Exception as ex:
            log.warning("IOC feed %s failed: %s", name, ex)
            statuses.append({"source": name, "ok": False, "count": 0, "error": str(ex)[:80]})
    return statuses

# --- DATE HELPER ---
def parse_flexible_date(date_obj):
    now = datetime.datetime.now(IL_TZ)
    try:
        if isinstance(date_obj, time.struct_time):
            dt = datetime.datetime(*date_obj[:6], tzinfo=pytz.utc)
            return dt.astimezone(IL_TZ).isoformat()
        if isinstance(date_obj, str):
            dt = date_parser.parse(date_obj)
            if dt.tzinfo is None: dt = pytz.utc.localize(dt)
            return dt.astimezone(IL_TZ).isoformat()
        if isinstance(date_obj, datetime.datetime):
            if date_obj.tzinfo is None: date_obj = pytz.utc.localize(date_obj)
            return date_obj.astimezone(IL_TZ).isoformat()
    except Exception as e:
        log.debug("parse_flexible_date failed for %r: %s", date_obj, e)
    return now.isoformat()

def is_recent(date_str):
    """Checks if an ISO date string is within the HISTORY_DAYS window."""
    try:
        dt = date_parser.parse(date_str)
        if dt.tzinfo is None: dt = pytz.utc.localize(dt)
        limit = datetime.datetime.now(dt.tzinfo) - datetime.timedelta(days=HISTORY_DAYS)
        return dt > limit
    except Exception as e:
        log.debug("is_recent could not parse %r: %s", date_str, e)
        return True  # If unsure, keep it

# --- IOC VALIDATION ---
def identify_ioc_type(ioc):
    ioc = ioc.strip()
    if re.match(r'^https?://', ioc) or re.match(r'^www\.', ioc): return "url"
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError: pass
    if re.match(r'^[a-fA-F0-9]{32}$', ioc) or re.match(r'^[a-fA-F0-9]{40}$', ioc) or re.match(r'^[a-fA-F0-9]{64}$', ioc): return "hash"
    if re.match(r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$', ioc): return "domain"
    return None

# --- DATABASE MANAGEMENT ---
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS intel_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        published_at TEXT,
        source TEXT,
        url TEXT UNIQUE,
        title TEXT,
        category TEXT,
        severity TEXT,
        summary TEXT,
        actor_tag TEXT,
        tags TEXT
    )''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_url ON intel_reports(url)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_title ON intel_reports(title)")

    # Live IOC feed — one row per (value, source report); the UI groups by value.
    c.execute('''CREATE TABLE IF NOT EXISTS iocs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        value TEXT,
        ioc_type TEXT,
        severity TEXT,
        tags TEXT,
        israel INTEGER DEFAULT 0,
        source TEXT,
        report_url TEXT,
        report_title TEXT,
        first_seen TEXT,
        UNIQUE(value, report_url)
    )''')
    c.execute("CREATE INDEX IF NOT EXISTS idx_ioc_value ON iocs(value)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_ioc_seen ON iocs(first_seen)")
    # hourly-gate bookkeeping for the dedicated IOC feeds (multi-MB downloads)
    c.execute('''CREATE TABLE IF NOT EXISTS ioc_feed_meta (
        source TEXT PRIMARY KEY,
        last_fetch TEXT
    )''')

    # Strict cleanup of old data (INCD Alerts kept like INCD — national CERT)
    limit_regular = (datetime.datetime.now(IL_TZ) - datetime.timedelta(days=HISTORY_DAYS)).isoformat()
    c.execute("DELETE FROM intel_reports WHERE source NOT IN ('INCD', 'INCD Alerts', 'DeepWeb') AND published_at < ?", (limit_regular,))
    # IOCs age out with the same window, except Israel-priority ones (kept like INCD reports)
    c.execute("DELETE FROM iocs WHERE israel = 0 AND first_seen < ?", (limit_regular,))
    conn.commit()
    conn.close()
    # Self-heal: re-classify stored reports with the current bilingual rules —
    # rows saved by older keyword sets were stuck on General/Medium, which
    # emptied the tag filters (owner-reported: "Israel shows nothing").
    retag_reports()
    # Self-heal: when the denylist grows, retroactively purge stored IOCs that
    # are no longer considered blockable (e.g. a URL shortener that slipped in).
    _purge_denied_iocs()
    # Idempotent: make sure IOCs exist for already-stored RAW reports (e.g. after
    # this upgrade, or a cloud cold-start restoring from feeds without AI).
    backfill_iocs()

def get_existing_data():
    try:
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT url, title FROM intel_reports")
        rows = c.fetchall()
        conn.close()
        return {row[0] for row in rows}, {row[1] for row in rows}
    except Exception as e:
        log.warning("get_existing_data failed: %s", e)
        return set(), set()

# --- DEEP WEB SCANNER ---
class DeepWebScanner:
    def scan_actor(self, actor_name, limit=3):
        results = []
        try:
            query = f'"{actor_name}" cyber threat intelligence malware analysis report'
            with DDGS() as ddgs:
                ddg_results = list(ddgs.text(query, max_results=limit))
                existing_urls, _ = get_existing_data()
                for res in ddg_results:
                    url = res.get('href')
                    if url in existing_urls: continue
                    results.append({
                        "title": res.get('title'),
                        "url": url,
                        "date": datetime.datetime.now(IL_TZ).isoformat(),
                        "source": "DeepWeb",
                        "summary": res.get('body', 'No summary available.'),
                        "actor_tag": actor_name
                    })
        except Exception as e:
            log.warning("DeepWeb scan failed for %s: %s", actor_name, e)
        return results

# --- CONNECTION & AI ENGINES ---
class ConnectionManager:
    @staticmethod
    def check_groq(key):
        """Instant, offline format check — used as the status shown before the
        first real ping completes. 'Configured' != reachable; see ping_groq."""
        if not key: return False, "Missing Key"
        if key.startswith("gsk_"): return True, "Configured"
        return False, "Invalid Format"

    @staticmethod
    async def ping_groq(key):
        """Real Groq reachability check via the free models endpoint (no token
        cost). Returns (ok, status_message). Run once per boot/sync and cached in
        session_state so it does not fire on every rerun."""
        if not key:
            return False, "Missing Key"
        if not key.startswith("gsk_"):
            return False, "Invalid Format"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    "https://api.groq.com/openai/v1/models",
                    headers={"Authorization": f"Bearer {key}"},
                    timeout=10,
                ) as resp:
                    if resp.status == 200:
                        return True, "Connected"
                    if resp.status in (401, 403):
                        return False, "Invalid Key"
                    return False, f"Unreachable ({resp.status})"
        except Exception as e:
            log.debug("Groq ping failed: %s", e)
            return False, "Unreachable"

async def query_groq_api(api_key, prompt, model="llama-3.3-70b-versatile", json_mode=True):
    if not api_key: return "Error: Missing API Key"
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    models = [model, "llama-3.1-8b-instant"]
    for m in models:
        payload = {"model": m, "messages": [{"role": "user", "content": prompt}], "temperature": 0.1}
        if json_mode: payload["response_format"] = {"type": "json_object"}
        # Retry the SAME model on rate-limit (429) with a short exponential backoff
        # before falling back to the next model. Free-tier bursts hit 429 a lot;
        # without this the whole chunk silently degrades to RAW (the "half the
        # cards are English" symptom). Backoff is kept short so that when the quota
        # is genuinely exhausted we fail fast to RAW rather than hanging the boot.
        for attempt in range(2):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(url, json=payload, headers=headers, timeout=30) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            return data['choices'][0]['message']['content']
                        if resp.status == 429:
                            # CAP the wait. On daily-quota exhaustion Groq returns 429
                            # with a huge Retry-After (thousands of seconds); honoring it
                            # verbatim HANGS the boot. Cap hard (<=5s) so we fail fast to
                            # RAW and let the next sync retry once the quota resets.
                            ra = resp.headers.get("retry-after")
                            try:
                                delay = float(ra) if ra else 2 ** attempt
                            except ValueError:
                                delay = 2 ** attempt
                            delay = min(delay, 5)
                            log.warning("Groq 429 (model=%s, attempt %d) — backing off %.1fs", m, attempt + 1, delay)
                            await asyncio.sleep(delay)
                            continue
                        log.warning("Groq HTTP %s (model=%s)", resp.status, m)
                        break  # non-retryable -> try the next model
            except Exception as e:
                log.warning("Groq request failed (model=%s, attempt %d): %s", m, attempt + 1, e)
                await asyncio.sleep(min(2 ** attempt, 5))
    return None

class AIBatchProcessor:
    def __init__(self, key):
        self.key = key

    # Bilingual keyword sets — roughly half the feed is Hebrew (INCD, Cyber News
    # IL, People & Computers), and English-only keywords left every Hebrew item
    # tagged "General"/Medium (which emptied the Israel/Malware/... filters).
    _KW_HIGH = ('exploited', 'zero-day', 'ransomware', 'critical', 'cve-202', 'apt',
                'state-sponsored', 'כופרה', 'קריטי', 'מנוצל', 'חירום', 'התרעה')
    _KW_ISRAEL = ('israel', 'iran', 'ישראל', 'ישראלי', 'איראן', 'מערך הסייבר', 'פיקוד העורף', 'צה"ל')
    _KW_VULN = ('cve-', 'patch', 'vulnerability', 'vulnerabilit', 'flaw', 'security bug',
                'zero-day', 'exploit', 'פגיעות', 'חולשה', 'חולשות', 'עדכון אבטחה')
    _KW_PHISH = ('phishing', 'credential', 'scam', 'fraud', 'smishing', 'impersonat',
                 'פישינג', 'דיוג', 'התחזות', 'הונאה', 'הונאות')
    _KW_MAL = ('malware', 'ransomware', 'trojan', 'backdoor', 'stealer', 'botnet',
               'spyware', 'rootkit', ' rat ', 'loader', 'נוזקה', 'נוזקות', 'כופרה',
               'סוס טרויאני', 'בוטנט')
    _KW_RESEARCH = ('research', 'analysis', 'מחקר', 'ניתוח')
    INCD_SOURCES = ("INCD", "INCD Alerts")

    def _determine_tag_severity(self, text, source):
        text = f" {str(text).lower()} "
        sev, tag = "Medium", "General"
        if any(x in text for x in self._KW_HIGH): sev = "High"
        if source in self.INCD_SOURCES or any(x in text for x in self._KW_ISRAEL): tag = "Israel"
        elif any(x in text for x in self._KW_VULN): tag = "Vulnerabilities"
        elif any(x in text for x in self._KW_PHISH): tag = "Phishing"
        elif any(x in text for x in self._KW_MAL): tag = "Malware"
        elif any(x in text for x in self._KW_RESEARCH): tag = "Research"
        if source in self.INCD_SOURCES:  # national cyber directorate alerts are always high-priority
            sev = "High"
        return tag, sev

    def is_similar(self, a, b, threshold=0.75):
        return SequenceMatcher(None, a, b).ratio() > threshold

    def _raw_result(self, original):
        """Build a RAW (no-AI) feed item from a fetched source item — used both
        when the whole chunk has no AI output and when a single AI summary comes
        back empty."""
        raw_title = original.get('title') or ""
        raw_summary = original.get('summary') or ""
        tag, sev = self._determine_tag_severity(f"{raw_title} {raw_summary}", original['source'])
        return {
            "category": "Raw", "severity": sev,
            "title": raw_title, "summary": raw_summary,
            "published_at": original['date'],
            "source": original['source'], "url": original['url'],
            "actor_tag": original.get('actor_tag', None), "tags": tag,
        }

    async def analyze_batch(self, items):
        if not items: return []
        existing_urls, existing_titles = get_existing_data()

        items_to_process = [i for i in items if i['url'] not in existing_urls and not is_noise(i)]
        if not items_to_process: return []

        # Cross-source de-duplication (token-set + shared-CVE). Process richer
        # items (longer summary) first so the most informative copy of a story is
        # the one kept; the terse duplicates from other outlets are dropped.
        items_to_process.sort(key=lambda i: len(i.get('summary') or ''), reverse=True)
        existing_sigs = [(_norm_tokens(t), _cve_ids(t)) for t in existing_titles]
        unique_items, kept_sigs = [], []
        for item in items_to_process:
            sig = _signature(item)
            if any(is_duplicate(sig, es) for es in existing_sigs):
                continue
            if any(is_duplicate(sig, ks) for ks in kept_sigs):
                continue
            unique_items.append(item)
            kept_sigs.append(sig)

        if not unique_items: return []

        # Chunk size + per-item content are bounded so the batch prompt fits the
        # SMALLER fallback model too: with 10×1500 chars the llama-3.1-8b-instant
        # fallback died with HTTP 413 (payload too large) exactly when it was
        # needed (70b rate-limited), silently degrading chunks to RAW.
        chunk_size = 6
        results = []

        system_instruction = """
        You are a senior SOC / Cyber Threat Intelligence analyst writing for an Israeli security team.

        **MISSION:**
        1. Analyze each news item and write a short operational brief.
        2. MERGE two items ONLY if they describe the EXACT same event (same victim + same attack). When unsure, keep them separate.
        3. NEVER discard a unique item.

        **OUTPUT LANGUAGE:** Hebrew ONLY. Keep technical terms, product names, CVE ids and malware/actor names in English.

        **WRITING RULES (this fixes thin, inconsistent cards):**
        - EVERY item uses the EXACT same 4 sections below, in the same order, with the same labels.
        - Every section MUST contain a real, informative sentence — never leave one empty and never output just a list of keywords. If a detail is genuinely missing from the source, write a short analyst note (e.g. "לא פורסמו פרטים טכניים נוספים") instead of leaving it blank.
        - Be concrete: name the victim/target, the attacker/campaign, the attack vector, affected products/versions, and CVE ids when present.
        - Keep each section to 1-2 tight sentences so the whole summary reads well on a feed card.

        **REPORT STRUCTURE (return JSON only):**
        {"items": [
            {
                "id": (int) ID matching the input,
                "title": "כותרת מקצועית, ברורה וספציפית בעברית",
                "summary": "• **תמונת מצב**: מה קרה — מי הותקף/מי התוקף ומתי.\n• **ממצאים טכניים**: CVE, נוזקות, וקטור תקיפה ומערכות מושפעות.\n• **המלצות הגנה**: פעולה קונקרטית (עדכון/חסימה/ציד איומים).\n• **רלוונטיות ל-SOC**: רמת הסיכון ולמה זה חשוב לצוות."
            }
        ]}
        """

        for i in range(0, len(unique_items), chunk_size):
            chunk = unique_items[i:i+chunk_size]
            chunk_results = []

            # --- AI path (only if a key is configured) ---
            if self.key:
                batch_text = "\n".join([f"ID:{idx} | Title: {x['title']} | Content: {x['summary'][:700]}" for idx, x in enumerate(chunk)])
                prompt = f"{system_instruction}\n\nDATA:\n{batch_text}"

                res = await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=True)

                if res:
                    try:
                        data = json.loads(res)
                        for p_item in data.get("items", []):
                            idx = p_item.get('id')
                            if idx is not None and 0 <= idx < len(chunk):
                                original = chunk[idx]

                                # Groq already returns operational Hebrew; the former
                                # google-generativeai "polish" pass was end-of-life and removed.
                                final_title = p_item.get('title') or ""
                                final_summary = p_item.get('summary') or ""

                                # The model sometimes returns the bullet template with
                                # every section empty -> show the raw source text instead
                                # of empty bullets.
                                if _is_empty_ai_summary(final_summary):
                                    log.info("empty AI summary -> raw fallback: %s", original['url'])
                                    chunk_results.append(self._raw_result(original))
                                    continue

                                # Tag/severity from the RAW source text — the AI output is
                                # Hebrew, so classifying it hid the English keywords and
                                # left every AI item as General/Medium.
                                raw_text = f"{original.get('title', '')} {original.get('summary', '')}"
                                final_tag, final_sev = self._determine_tag_severity(raw_text, original['source'])

                                chunk_results.append({
                                    "category": "News", "severity": final_sev,
                                    "title": final_title, "summary": final_summary,
                                    "published_at": original['date'],
                                    "source": original['source'], "url": original['url'],
                                    "actor_tag": original.get('actor_tag', None), "tags": final_tag
                                })
                    except Exception as e:
                        log.warning("failed to parse Groq JSON response: %s", e)

            # --- Graceful degradation ---
            # If the AI produced nothing for this chunk (no key, Groq error, or an
            # unparseable response), keep the RAW fetched items so the feed still
            # shows real intel instead of going blank. Tag/severity stay rule-based.
            if not chunk_results:
                if not self.key:
                    log.info("no Groq key: showing %d raw item(s) without AI summary", len(chunk))
                else:
                    log.warning("Groq returned no usable output: falling back to %d raw item(s)", len(chunk))
                for original in chunk:
                    chunk_results.append(self._raw_result(original))

            results.extend(chunk_results)
            # Space out AI calls so a burst of chunks doesn't trip free-tier rate
            # limits (which would degrade later chunks to RAW).
            if self.key and i + chunk_size < len(unique_items):
                await asyncio.sleep(2)

        return results

    async def analyze_single_ioc(self, ioc, ioc_type, data):
        lean_data = self._extract_key_intel(data)
        prompt = f"Act as Senior SOC Analyst. Target: {ioc} ({ioc_type}). Data: {json.dumps(lean_data)}. Output Hebrew Markdown analysis."
        res = await query_groq_api(self.key, prompt, model="llama-3.3-70b-versatile", json_mode=False)
        return res if res else "Analysis unavailable."

    def _extract_key_intel(self, raw_data):
        summary = {}
        if 'virustotal' in raw_data and raw_data['virustotal']:
            vt = raw_data['virustotal']
            summary['virustotal'] = {'malicious_votes': vt.get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0), 'tags': vt.get('attributes', {}).get('tags', [])}
        return summary

class ThreatLookup:
    def __init__(self, vt_key=None, urlscan_key=None, abuse_key=None):
        self.vt_key, self.urlscan_key, self.abuse_key = vt_key, urlscan_key, abuse_key
    def query_virustotal(self, ioc, ioc_type):
        if not self.vt_key: return None
        try:
            endpoint = f"urls/{base64.urlsafe_b64encode(ioc.encode()).decode().strip('=')}" if ioc_type == "url" else f"{'ip_addresses' if ioc_type == 'ip' else 'domains' if ioc_type == 'domain' else 'files'}/{ioc}"
            res = requests.get(f"https://www.virustotal.com/api/v3/{endpoint}", headers={"x-apikey": self.vt_key}, timeout=10)
            return res.json().get('data', {}) if res.status_code == 200 else None
        except Exception as e:
            log.warning("VirusTotal query failed for %s: %s", ioc, e)
            return None
    def query_urlscan(self, ioc):
        if not self.urlscan_key: return None
        try:
            res = requests.get(f"https://urlscan.io/api/v1/search/?q=\"{ioc}\"", headers={"API-Key": self.urlscan_key}, timeout=10)
            data = res.json()
            if data.get('results'):
                return requests.get(f"https://urlscan.io/api/v1/result/{data['results'][0]['_id']}/", headers={"API-Key": self.urlscan_key}, timeout=10).json()
            return None
        except Exception as e:
            log.warning("URLScan query failed for %s: %s", ioc, e)
            return None
    def query_abuseipdb(self, ip):
        if not self.abuse_key: return None
        try:
            return requests.get("https://api.abuseipdb.com/api/v2/check", headers={'Key': self.abuse_key}, params={'ipAddress': ip}, timeout=10).json().get('data', {})
        except Exception as e:
            log.warning("AbuseIPDB query failed for %s: %s", ip, e)
            return None

class AnalystToolkit:
    @staticmethod
    def get_tools():
        return {
            "Analysis": [{"name": "CyberChef", "url": "https://gchq.github.io/CyberChef/", "desc": "פענוח", "icon": "🔪"},{"name": "Any.Run", "url": "https://app.any.run/", "desc": "Sandbox", "icon": "📦"},{"name": "UnpacMe", "url": "https://www.unpac.me/", "desc": "Unpacking", "icon": "🔓"}],
            "Lookup": [{"name": "VirusTotal", "url": "https://www.virustotal.com/", "desc": "Scanner", "icon": "🦠"},{"name": "AbuseIPDB", "url": "https://www.abuseipdb.com/", "desc": "Reputation", "icon": "🚫"},{"name": "Talos", "url": "https://talosintelligence.com/", "desc": "Intel", "icon": "🛡️"}],
            "Tools": [{"name": "MxToolbox", "url": "https://mxtoolbox.com/", "desc": "Network", "icon": "🔧"},{"name": "URLScan", "url": "https://urlscan.io/", "desc": "Web Scan", "icon": "📷"},{"name": "OTX", "url": "https://otx.alienvault.com/", "desc": "Open Intel", "icon": "👽"}]
        }

class APTSheetCollector:
    def fetch_threats(self):
        return [
            {"name": "MuddyWater", "origin": "Iran (MOIS)", "target": "Israel", "type": "Espionage", "tools": "PowerShell, Ligolo", "desc": "Linked to Iran's Ministry of Intelligence (MOIS)."},
            {"name": "OilRig (APT34)", "origin": "Iran (IRGC)", "target": "Israel", "type": "Espionage", "tools": "DNSpionage", "desc": "Targets critical infrastructure."},
            {"name": "Agonizing Serpens", "origin": "Iran", "target": "Israel", "type": "Wiper", "tools": "BiBiWiper", "desc": "Data-destruction (wiper) operations."}
        ]

class CTICollector:
    SOURCES = [
        # --- General / international news ---
        {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/", "type": "rss"},
        {"name": "TheHackerNews", "url": "https://feeds.feedburner.com/TheHackersNews", "type": "rss"},
        {"name": "Malwarebytes", "url": "https://www.malwarebytes.com/blog/feed/", "type": "rss"},
        {"name": "SecurityWeek", "url": "https://www.securityweek.com/feed/", "type": "rss"},
        {"name": "Security Affairs", "url": "https://securityaffairs.com/feed", "type": "rss"},
        {"name": "GBHackers", "url": "https://gbhackers.com/feed/", "type": "rss"},
        {"name": "Dark Reading", "url": "https://www.darkreading.com/rss.xml", "type": "rss"},
        # --- Top-tier threat research ---
        {"name": "Unit 42", "url": "https://unit42.paloaltonetworks.com/feed/", "type": "rss"},
        {"name": "SANS ISC", "url": "https://isc.sans.edu/rssfeed_full.xml", "type": "rss"},
        {"name": "Securelist", "url": "https://securelist.com/feed/", "type": "rss"},
        {"name": "Talos", "url": "https://blog.talosintelligence.com/rss/", "type": "rss"},
        {"name": "Check Point", "url": "https://research.checkpoint.com/feed/", "type": "rss"},
        {"name": "ESET", "url": "https://www.welivesecurity.com/en/rss/feed/", "type": "rss"},
        {"name": "Mandiant", "url": "https://www.mandiant.com/resources/blog/rss.xml", "type": "rss"},
        {"name": "Krebs", "url": "https://krebsonsecurity.com/feed/", "type": "rss"},
        {"name": "Schneier", "url": "https://www.schneier.com/feed/atom/", "type": "rss"},
        {"name": "DFIR Report", "url": "https://thedfirreport.com/feed/", "type": "rss"},
        {"name": "Project Zero", "url": "https://googleprojectzero.blogspot.com/feeds/posts/default", "type": "rss"},
        {"name": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "type": "json"},
        # --- Israel / Hebrew ---
        {"name": "People & Computers", "url": "https://www.pc.co.il/feed/", "type": "rss"},
        {"name": "Cyber News IL", "url": "https://rss.app/feeds/Ho4gIVhEXQwiIoOx.xml", "type": "rss"},
        {"name": "CyberSafe", "url": "https://cybersafe.co.il/category/%D7%97%D7%93%D7%A9%D7%95%D7%AA-%D7%A1%D7%99%D7%99%D7%91%D7%A8/feed/", "type": "rss"},
        {"name": "Techz", "url": "https://techz.co.il/tag/%D7%A1%D7%99%D7%99%D7%91%D7%A8/feed/", "type": "rss"},
        {"name": "INCD", "url": "https://www.gov.il/he/rss/news_list?officeId=4bcc13f5-fed6-4b8c-b8ee-7bf4a6bc81c8", "type": "rss"},
        {"name": "INCD", "url": "https://t.me/s/Israel_Cyber", "type": "telegram"},
        {"name": "INCD Alerts", "url": "https://t.me/s/CyberGovIL", "type": "telegram"},
    ]

    async def fetch_item(self, session, source):
        """Fetch one source. Returns a status dict so callers can surface failures:
        {source, url, ok, items, error}. ok=False means the source did NOT load
        (vs. ok=True with an empty list, which means "loaded, nothing recent")."""
        items = []
        try:
            async with session.get(source['url'], headers=get_headers(), timeout=30) as resp:
                if resp.status != 200:
                    log.warning("source %s returned HTTP %s", source['name'], resp.status)
                    return {"source": source['name'], "url": source['url'], "ok": False, "items": [], "error": f"HTTP {resp.status}"}
                content = await resp.text()

                if source['type'] == 'rss':
                    feed = feedparser.parse(content)
                    # --- FETCH LIMIT = 100 ---
                    for entry in feed.entries[:FETCH_LIMIT]:
                        link = getattr(entry, 'link', None)
                        if not link:
                            continue
                        date_raw = getattr(entry, 'published_parsed', None) or getattr(entry, 'updated_parsed', None)
                        pub_date = parse_flexible_date(date_raw)

                        # --- STRICT 7-DAY FILTER ---
                        if is_recent(pub_date):
                            items.append({"title": getattr(entry, 'title', '(no title)'), "url": link, "date": pub_date, "source": source['name'], "summary": _entry_summary(entry)})

                elif source['type'] == 'json':
                     data = json.loads(content)
                     # Fetch more to allow date filtering
                     for v in data.get('vulnerabilities', [])[:50]:
                         pub_date = parse_flexible_date(v.get('dateAdded'))
                         if is_recent(pub_date):
                             items.append({"title": f"KEV: {v['cveID']}", "url": f"https://nvd.nist.gov/vuln/detail/{v['cveID']}", "date": pub_date, "source": "CISA", "summary": v.get('shortDescription')})

                elif source['type'] == 'telegram':
                    soup = BeautifulSoup(content, 'html.parser')
                    for msg in soup.find_all('div', class_='tgme_widget_message_wrap')[-50:]:
                        try:
                            time_tag = msg.find('time')
                            date_raw = time_tag['datetime'] if time_tag else None
                            pub_date = parse_flexible_date(date_raw)
                            text_div = msg.find('div', class_='tgme_widget_message_text')
                            link_tag = msg.find('a', class_='tgme_widget_message_date')
                            if not text_div or not link_tag:
                                continue
                            # INCD/Telegram alerts are kept regardless of the 7-day window
                            # (low volume, national-CERT priority) so the newest all appear.
                            _t = text_div.get_text(separator=' ').strip()
                            # A distinct per-post title; a constant title would collapse every
                            # alert into one under the title-similarity de-duplication.
                            _title = (_t[:80].rstrip() + '…') if len(_t) > 80 else (_t or "INCD Cyber Alert")
                            items.append({"title": _title, "url": link_tag['href'], "date": pub_date, "source": "INCD", "summary": _t})
                        except Exception as e:
                            log.debug("telegram message parse skipped: %s", e)
        except Exception as e:
            log.warning("source fetch failed: %s (%s): %s", source['name'], source['url'], e)
            return {"source": source['name'], "url": source['url'], "ok": False, "items": [], "error": str(e)}
        return {"source": source['name'], "url": source['url'], "ok": True, "items": items, "error": None}

    async def get_all_data(self):
        """Returns (items, statuses). `items` is the flat list of fetched reports;
        `statuses` is one entry per source so the UI can show source health."""
        async with aiohttp.ClientSession() as session:
            tasks = [self.fetch_item(session, s) for s in self.SOURCES]
            results = await asyncio.gather(*tasks)
        items = [it for r in results for it in r["items"]]
        statuses = [{"source": r["source"], "url": r["url"], "ok": r["ok"], "count": len(r["items"]), "error": r["error"]} for r in results]
        return items, statuses

def save_reports(raw, analyzed):
    conn = sqlite3.connect(DB_NAME)
    c, cnt = conn.cursor(), 0
    for item in analyzed:
        try:
            c.execute("INSERT OR IGNORE INTO intel_reports (timestamp,published_at,source,url,title,category,severity,summary,actor_tag,tags) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (datetime.datetime.now(IL_TZ).isoformat(), item['published_at'], item['source'], item['url'], item['title'], item['category'], item['severity'], item['summary'], item.get('actor_tag'), item.get('tags')))
            if c.rowcount > 0: cnt += 1
        except Exception as e:
            log.warning("failed to save report %s: %s", item.get('url'), e)
    conn.commit()
    conn.close()
    # Feed the Live IOC tab — extraction runs on the RAW source text (never the
    # AI summary) and is fully deterministic; safe to base blocking rules on.
    try:
        extract_and_save_iocs(raw, analyzed)
    except Exception as e:
        log.warning("IOC extraction during save failed: %s", e)
    return cnt
