"""Characterization tests — lock the CURRENT behavior of utils.py pure
functions BEFORE any Phase 1 refactor. These assert what the code does today
(quirks included), so a later refactor can't silently change behavior.
"""
import os
import sys
import time as _time
import datetime
from datetime import timedelta

import pytz
from dateutil import parser as date_parser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import utils  # noqa: E402


# ---------------------------------------------------------------- IOC typing
class TestIdentifyIocType:
    def test_ipv4(self):
        assert utils.identify_ioc_type("8.8.8.8") == "ip"

    def test_ipv6(self):
        assert utils.identify_ioc_type("2001:db8::1") == "ip"

    def test_url_http(self):
        assert utils.identify_ioc_type("https://evil.example/path") == "url"

    def test_url_www(self):
        # current behavior: a leading www. is classified as url
        assert utils.identify_ioc_type("www.evil.example") == "url"

    def test_domain(self):
        assert utils.identify_ioc_type("evil.example") == "domain"

    def test_md5(self):
        assert utils.identify_ioc_type("d41d8cd98f00b204e9800998ecf8427e") == "hash"

    def test_sha1(self):
        assert utils.identify_ioc_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "hash"

    def test_sha256(self):
        assert utils.identify_ioc_type(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ) == "hash"

    def test_junk_is_none(self):
        assert utils.identify_ioc_type("not an ioc") is None

    def test_empty_is_none(self):
        assert utils.identify_ioc_type("") is None

    def test_whitespace_is_trimmed(self):
        assert utils.identify_ioc_type("  8.8.8.8  ") == "ip"


# ----------------------------------------------------------------- is_recent
class TestIsRecent:
    def test_now_is_recent(self):
        assert utils.is_recent(datetime.datetime.now(pytz.utc).isoformat()) is True

    def test_old_is_not_recent(self):
        assert utils.is_recent("2000-01-01T00:00:00") is False

    def test_unparseable_is_kept(self):
        # documented behavior: "if unsure, keep it" -> True
        assert utils.is_recent("definitely not a date") is True


# -------------------------------------------------------- parse_flexible_date
class TestParseFlexibleDate:
    def test_naive_string_is_utc_shown_in_israel(self):
        # June => Israel Daylight Time = UTC+3
        out = utils.parse_flexible_date("2026-06-01T12:00:00")
        dt = date_parser.parse(out)
        assert dt.utcoffset() == timedelta(hours=3)
        assert dt.astimezone(pytz.utc).replace(tzinfo=None) == datetime.datetime(2026, 6, 1, 12, 0, 0)

    def test_struct_time_is_utc_shown_in_israel(self):
        st = _time.struct_time((2026, 6, 1, 12, 0, 0, 0, 0, 0))
        dt = date_parser.parse(utils.parse_flexible_date(st))
        assert dt.utcoffset() == timedelta(hours=3)

    def test_unknown_type_falls_back_to_now(self):
        # an object that matches none of the branches -> returns "now" ISO string
        out = utils.parse_flexible_date(object())
        date_parser.parse(out)  # must be a parseable ISO timestamp


# --------------------------------------------- AIBatchProcessor tag/severity
class TestTagSeverity:
    def setup_method(self):
        self.p = utils.AIBatchProcessor("")

    def test_ransomware_is_high_but_general_tag(self):
        assert self.p._determine_tag_severity("ransomware hits hospital", "BleepingComputer") == ("כללי", "High")

    def test_cve_is_vuln_and_high(self):
        assert self.p._determine_tag_severity("New CVE-2024-1234 vulnerability", "X") == ("פגיעויות", "High")

    def test_iran_apt_is_israel_and_high(self):
        assert self.p._determine_tag_severity("Iran APT campaign", "X") == ("ישראל", "High")

    def test_phishing_is_medium(self):
        assert self.p._determine_tag_severity("phishing credential theft", "X") == ("פיישינג", "Medium")

    def test_malware_tag(self):
        assert self.p._determine_tag_severity("new trojan backdoor", "X") == ("נוזקה", "Medium")

    def test_research_tag(self):
        assert self.p._determine_tag_severity("deep threat research analysis", "X") == ("מחקר", "Medium")

    def test_incd_source_is_israel(self):
        assert self.p._determine_tag_severity("routine update", "INCD") == ("ישראל", "Medium")

    def test_default_is_general_medium(self):
        assert self.p._determine_tag_severity("nothing special here", "X") == ("כללי", "Medium")


# ------------------------------------------------- AIBatchProcessor similarity
class TestIsSimilar:
    def setup_method(self):
        self.p = utils.AIBatchProcessor("")

    def test_identical_titles_are_similar(self):
        assert self.p.is_similar("Microsoft patches zero-day", "Microsoft patches zero-day") is True

    def test_unrelated_titles_are_not_similar(self):
        assert self.p.is_similar("apple pie recipe", "quantum chromodynamics") is False
