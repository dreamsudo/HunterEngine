# -*- coding: utf-8 -*-
"""generate_report.py tests: STIX export safety and the data-driven tactic
table. Requires matplotlib/numpy (the report tool's own dependencies)."""
import json

import pytest

pytest.importorskip("matplotlib")
pytest.importorskip("numpy")
import generate_report as gr  # noqa: E402


def make_case(url, ipv4=None, secret="RAW MESSAGE CONTENT — MUST NOT LEAK"):
    indicators = {"urls": [url]}
    if ipv4:
        indicators["ipv4"] = [ipv4]
    return {
        "input": secret,
        "analysis": {"risk_score": 20, "risk_level": "CRITICAL", "tags": []},
        "indicators": indicators,
        "mitre_matches": [{"id": "T1566", "name": "Phishing",
                           "tactic": "initial-access"}],
    }


# --------------------------------------------------------------------------- #
# STIX pattern building (attacker-controlled IoC values)
# --------------------------------------------------------------------------- #
def test_stix_escape():
    assert gr._stix_escape(r"a'b\c") == r"a\'b\\c"


def test_stix_pattern_escapes_hostile_iocs():
    """Regression: a quote inside a URL used to break out of the STIX string
    literal — pattern injection into shareable intel."""
    pattern = gr._stix_pattern_for(
        {"urls": ["http://evil.example/pay?item=o'brien"],
         "ipv4": ["1.2.3.4"]}, defang=False)
    assert r"o\'brien" in pattern
    assert "[ipv4-addr:value = '1.2.3.4']" in pattern


def test_stix_pattern_includes_ipv4():
    """Regression: the exporter read key 'ips' while the engine emits 'ipv4',
    silently dropping every IP indicator."""
    pattern = gr._stix_pattern_for({"ipv4": ["10.0.0.1"]}, defang=False)
    assert "10.0.0.1" in pattern


def test_stix_pattern_defang():
    pattern = gr._stix_pattern_for({"urls": ["http://a.example/x"]}, defang=True)
    assert "hxxp://a[.]example/x" in pattern


def test_export_stix_bundle_valid_and_content_free(tmp_path, capsys):
    out = tmp_path / "bundle.json"
    items = [make_case("http://evil.example/pay?item=o'brien", ipv4="1.2.3.4")]
    count = gr.export_stix_bundle(items, str(out))
    assert count > 0
    raw = out.read_text(encoding="utf-8")
    bundle = json.loads(raw)
    assert bundle["type"] == "bundle"
    assert "RAW MESSAGE CONTENT" not in raw, "message text must never be shared"
    assert "ipv4-addr" in raw
    if gr._HAVE_STIX2:
        assert "stix2-validated" in capsys.readouterr().out, \
            "with stix2 installed, the bundle must pass validation (no fallback)"


# --------------------------------------------------------------------------- #
# Data-driven tactic table
# --------------------------------------------------------------------------- #
def test_load_tactics_prefers_cache(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    cache = {"tactics": [
        {"shortname": "stealth", "name": "Stealth", "taid": "TA0005"},
        {"shortname": "impact", "name": "Impact", "taid": "TA0040"},
    ]}
    (tmp_path / gr.MITRE_CACHE_FILE).write_text(json.dumps(cache),
                                                encoding="utf-8")
    assert gr._load_tactics() == [("stealth", "Stealth", "TA0005"),
                                  ("impact", "Impact", "TA0040")]


def test_load_tactics_falls_back_without_cache(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    tactics = gr._load_tactics()
    assert tactics == gr.FALLBACK_TACTICS
    shortnames = [s for s, _, _ in tactics]
    # Regression: the old hardcoded table predated the ATT&CK rename of
    # defense-evasion -> stealth and silently dropped the largest tactic.
    assert "stealth" in shortnames
    assert "defense-evasion" in shortnames  # kept for older datasets


def test_load_tactics_survives_malformed_cache(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / gr.MITRE_CACHE_FILE).write_text("{not json", encoding="utf-8")
    assert gr._load_tactics() == gr.FALLBACK_TACTICS


def test_ordered_present_tactics_ignores_unknown_values():
    items = [{"mitre_matches": [{"tactic": "initial-access"},
                                {"tactic": "not-a-real-tactic"},
                                {"tactic": "unknown"}]}]
    assert gr.ordered_present_tactics(items) == ["initial-access"]
